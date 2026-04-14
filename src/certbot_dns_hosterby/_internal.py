"""hoster.by DNS Authenticator plugin for Certbot.

This plugin fulfills DNS-01 challenges by managing TXT records through the
hoster.by DNS REST API.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import quote

import configobj
import requests
from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "https://serviceapi.hoster.by"
DEFAULT_TTL = 600
DEFAULT_TIMEOUT = 30


@dataclass(frozen=True)
class _Credentials:
    access_token: str | None = None
    access_key: str | None = None
    secret_key: str | None = None
    api_url: str | None = None


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for hoster.by."""

    description = (
        "Obtain certificates using a DNS TXT record "
        "(if you are using hoster.by for DNS)."
    )
    ttl = DEFAULT_TTL

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._credentials: _Credentials | None = None
        self._client: _HosterByClient | None = None
        self._orders_cache: list[dict[str, Any]] | None = None

    @classmethod
    def add_parser_arguments(cls, add: Any, default_propagation_seconds: int = 60) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="hoster.by credentials INI file.")
        add(
            "api-url",
            default=DEFAULT_API_URL,
            help="hoster.by API base URL. Defaults to https://serviceapi.hoster.by.",
        )
        add(
            "ttl",
            default=DEFAULT_TTL,
            type=int,
            help="TTL for created TXT records. Defaults to 600.",
        )

    def more_info(self) -> str:
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge "
            "using the hoster.by DNS API."
        )

    def _setup_credentials(self) -> None:
        self._configure_file("credentials", "hoster.by credentials INI file")
        credentials_path = self.conf("credentials")
        if not credentials_path:
            raise errors.PluginError("hoster.by credentials file is required.")

        dns_common.validate_file_permissions(credentials_path)

        try:
            conf = configobj.ConfigObj(credentials_path)
        except configobj.ConfigObjError as exc:
            raise errors.PluginError(
                f"Error parsing credentials configuration '{credentials_path}': {exc}"
            ) from exc

        access_token = _get_first(conf, [
            "dns_hosterby_access_token",
            "certbot_dns_hosterby:dns_hosterby_access_token",
        ])
        access_key = _get_first(conf, [
            "dns_hosterby_access_key",
            "certbot_dns_hosterby:dns_hosterby_access_key",
        ])
        secret_key = _get_first(conf, [
            "dns_hosterby_secret_key",
            "certbot_dns_hosterby:dns_hosterby_secret_key",
        ])
        api_url = _get_first(conf, [
            "dns_hosterby_api_url",
            "certbot_dns_hosterby:dns_hosterby_api_url",
        ])

        if not access_token and not (access_key and secret_key):
            raise errors.PluginError(
                "Credentials file must contain either dns_hosterby_access_token or both "
                "dns_hosterby_access_key and dns_hosterby_secret_key."
            )

        self._credentials = _Credentials(
            access_token=access_token,
            access_key=access_key,
            secret_key=secret_key,
            api_url=api_url,
        )
        self._client = None
        self._orders_cache = None

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        client = self._get_client()
        order = self._find_order(validation_name)
        order_id = _extract_order_id(order)
        record_fqdn = _ensure_trailing_dot(validation_name)
        txt_record = client.get_txt_record(order_id, record_fqdn)
        ttl = int(self.conf("ttl") or self.ttl)

        if txt_record is None:
            client.create_txt_record(order_id, record_fqdn, ttl, [validation])
            return

        existing_values = _extract_txt_values(txt_record)
        if validation in existing_values:
            logger.debug("TXT value already present for %s", validation_name)
            return

        existing_values.append(validation)
        client.update_txt_record(
            order_id=order_id,
            record_name_candidates=_record_name_candidates(record_fqdn),
            ttl=int(txt_record.get("ttl") or ttl),
            values=existing_values,
        )

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        try:
            client = self._get_client()
            order = self._find_order(validation_name)
            order_id = _extract_order_id(order)
            record_fqdn = _ensure_trailing_dot(validation_name)
            txt_record = client.get_txt_record(order_id, record_fqdn)
            if txt_record is None:
                logger.debug("No TXT record found during cleanup for %s", validation_name)
                return

            remaining_values = [value for value in _extract_txt_values(txt_record) if value != validation]
            if remaining_values:
                client.update_txt_record(
                    order_id=order_id,
                    record_name_candidates=_record_name_candidates(record_fqdn),
                    ttl=int(txt_record.get("ttl") or self.conf("ttl") or self.ttl),
                    values=remaining_values,
                )
            else:
                client.delete_txt_record(
                    order_id=order_id,
                    record_name_candidates=_record_name_candidates(record_fqdn),
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cleanup failed for %s: %s", validation_name, exc)

    def _get_client(self) -> "_HosterByClient":
        if self._credentials is None:
            raise errors.PluginError("Credentials have not been initialized.")

        if self._client is not None:
            return self._client

        api_url = (self._credentials.api_url or self.conf("api-url") or DEFAULT_API_URL).rstrip("/")
        client = _HosterByClient(api_url=api_url)

        if self._credentials.access_token:
            client.set_access_token(self._credentials.access_token)
        else:
            if not (self._credentials.access_key and self._credentials.secret_key):
                raise errors.PluginError(
                    "Missing hoster.by authentication details. Provide either access token or access key/secret key."
                )
            access_token = client.create_access_token(
                access_key=self._credentials.access_key,
                secret_key=self._credentials.secret_key,
            )
            client.set_access_token(access_token)

        self._client = client
        return client

    def _find_order(self, validation_name: str) -> dict[str, Any]:
        normalized_validation_name = _normalize_fqdn(validation_name)
        if self._orders_cache is None:
            self._orders_cache = self._get_client().list_orders()

        best_order: dict[str, Any] | None = None
        best_len = -1
        for order in self._orders_cache:
            domain_name = _normalize_fqdn(str(order.get("domainName", "")))
            if not domain_name:
                continue
            if normalized_validation_name == domain_name or normalized_validation_name.endswith("." + domain_name):
                if len(domain_name) > best_len:
                    best_order = order
                    best_len = len(domain_name)

        if best_order is None:
            raise errors.PluginError(
                f"Unable to find matching hoster.by DNS order for {validation_name}."
            )
        return best_order


class _HosterByClient:
    def __init__(self, api_url: str, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": "certbot-dns-hosterby/0.1.0",
            }
        )
        self._access_token: str | None = None

    def set_access_token(self, access_token: str) -> None:
        self._access_token = access_token

    def create_access_token(self, access_key: str, secret_key: str) -> str:
        data = self._request(
            method="POST",
            path="/service/account/create/token",
            headers={
                "Access-Key": access_key,
                "Secret-Key": secret_key,
            },
            include_access_token=False,
        )
        try:
            return str(data["payload"]["accessToken"])
        except Exception as exc:  # noqa: BLE001
            raise errors.PluginError(
                "hoster.by token creation response did not include payload.accessToken."
            ) from exc

    def list_orders(self) -> list[dict[str, Any]]:
        data = self._request("GET", "/dns/orders")
        orders = data.get("payload", {}).get("orders", [])
        if not isinstance(orders, list):
            raise errors.PluginError("Unexpected hoster.by response format for DNS orders list.")
        return [order for order in orders if isinstance(order, dict)]

    def list_txt_records(self, order_id: int) -> list[dict[str, Any]]:
        data = self._request("GET", f"/dns/orders/{order_id}/records/txt")
        records = data.get("payload", {}).get("records", [])
        if not isinstance(records, list):
            raise errors.PluginError("Unexpected hoster.by response format for TXT records list.")
        return [record for record in records if isinstance(record, dict)]

    def get_txt_record(self, order_id: int, record_fqdn: str) -> dict[str, Any] | None:
        normalized_record_fqdn = _normalize_fqdn(record_fqdn)
        for record in self.list_txt_records(order_id):
            record_name = str(record.get("name", ""))
            if _normalize_fqdn(record_name) == normalized_record_fqdn:
                return record
        return None

    def create_txt_record(self, order_id: int, record_fqdn: str, ttl: int, values: list[str]) -> None:
        payload = {
            "name": _ensure_trailing_dot(record_fqdn),
            "ttl": int(ttl),
            "records": _format_records(values),
        }
        self._request("POST", f"/dns/orders/{order_id}/records/txt", json_body=payload)

    def update_txt_record(
        self,
        order_id: int,
        record_name_candidates: Iterable[str],
        ttl: int,
        values: list[str],
    ) -> None:
        payload = {
            "ttl": int(ttl),
            "records": _format_records(values),
        }
        self._try_record_name_candidates(
            method="PATCH",
            order_id=order_id,
            record_name_candidates=record_name_candidates,
            json_body=payload,
        )

    def delete_txt_record(self, order_id: int, record_name_candidates: Iterable[str]) -> None:
        self._try_record_name_candidates(
            method="DELETE",
            order_id=order_id,
            record_name_candidates=record_name_candidates,
        )

    def _try_record_name_candidates(
        self,
        method: str,
        order_id: int,
        record_name_candidates: Iterable[str],
        json_body: dict[str, Any] | None = None,
    ) -> None:
        last_error: Exception | None = None
        seen: set[str] = set()
        for candidate in record_name_candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            encoded_name = quote(candidate, safe="")
            path = f"/dns/orders/{order_id}/records/txt/{encoded_name}"
            try:
                self._request(method, path, json_body=json_body)
                return
            except errors.PluginError as exc:
                last_error = exc
                logger.debug("hoster.by %s failed for candidate '%s': %s", method, candidate, exc)

        if last_error is not None:
            raise last_error
        raise errors.PluginError("No valid hoster.by TXT record name candidate was available.")

    def _request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        include_access_token: bool = True,
    ) -> dict[str, Any]:
        request_headers = dict(headers or {})
        if include_access_token:
            if not self._access_token:
                raise errors.PluginError("hoster.by access token is not set.")
            request_headers.setdefault("Access-Token", self._access_token)

        url = f"{self.api_url}{path}"
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                json=json_body,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise errors.PluginError(f"Error communicating with hoster.by API: {exc}") from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise errors.PluginError(
                f"hoster.by API returned non-JSON response for {method} {path}: HTTP {response.status_code}"
            ) from exc

        if response.status_code >= 400 or str(data.get("statusCode", "")).lower() == "error":
            raise errors.PluginError(self._extract_error_message(data, response.status_code, method, path))

        return data

    @staticmethod
    def _extract_error_message(
        data: dict[str, Any],
        status_code: int,
        method: str,
        path: str,
    ) -> str:
        message_list = data.get("messageList", {})
        if isinstance(message_list, dict):
            error_messages = message_list.get("error")
            if isinstance(error_messages, dict) and error_messages:
                joined = "; ".join(f"{key}: {value}" for key, value in error_messages.items())
                return f"hoster.by API error for {method} {path}: {joined}"
        code_list = data.get("codeList", {})
        if isinstance(code_list, dict):
            errors_list = code_list.get("error")
            if errors_list:
                return f"hoster.by API error for {method} {path}: {errors_list}"
        return f"hoster.by API error for {method} {path}: HTTP {status_code}"


def _get_first(conf: configobj.ConfigObj, keys: list[str]) -> str | None:
    for key in keys:
        value = conf.get(key)
        if value:
            return str(value)
    return None


def _normalize_fqdn(name: str) -> str:
    return str(name).strip().rstrip(".").lower()


def _ensure_trailing_dot(name: str) -> str:
    normalized = str(name).strip()
    return normalized if normalized.endswith(".") else normalized + "."


def _record_name_candidates(record_fqdn: str) -> list[str]:
    fqdn = _ensure_trailing_dot(record_fqdn)
    normalized = _normalize_fqdn(record_fqdn)
    return [fqdn, normalized]


def _quote_txt_value(value: str) -> str:
    text = str(value)
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return text
    return f'"{text}"'


def _unquote_txt_value(value: str) -> str:
    text = str(value)
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text


def _format_records(values: list[str]) -> list[dict[str, Any]]:
    return [{"content": _quote_txt_value(value), "disabled": False} for value in values]


def _extract_txt_values(record: dict[str, Any]) -> list[str]:
    items = record.get("records", [])
    if not isinstance(items, list):
        raise errors.PluginError("Unexpected hoster.by TXT record payload format.")
    values: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if content is None:
            continue
        values.append(_unquote_txt_value(str(content)))
    return values


def _extract_order_id(order: dict[str, Any]) -> int:
    order_id = order.get("id")
    try:
        return int(order_id)
    except (TypeError, ValueError) as exc:
        raise errors.PluginError(f"Invalid hoster.by DNS order id: {order_id!r}") from exc
