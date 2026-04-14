from certbot_dns_hosterby._internal import (
    _ensure_trailing_dot,
    _extract_txt_values,
    _format_records,
    _normalize_fqdn,
    _quote_txt_value,
    _record_name_candidates,
    _unquote_txt_value,
)


def test_normalize_fqdn():
    assert _normalize_fqdn("_AcMe.Example.COM.") == "_acme.example.com"


def test_ensure_trailing_dot():
    assert _ensure_trailing_dot("example.com") == "example.com."
    assert _ensure_trailing_dot("example.com.") == "example.com."


def test_quote_unquote_txt_value():
    assert _quote_txt_value("token") == '"token"'
    assert _quote_txt_value('"token"') == '"token"'
    assert _unquote_txt_value('"token"') == "token"
    assert _unquote_txt_value("token") == "token"


def test_format_records():
    assert _format_records(["abc"]) == [{"content": '"abc"', "disabled": False}]


def test_extract_txt_values():
    record = {
        "records": [
            {"content": '"one"', "disabled": False},
            {"content": '"two"', "disabled": False},
        ]
    }
    assert _extract_txt_values(record) == ["one", "two"]


def test_record_name_candidates():
    assert _record_name_candidates("_acme.example.com") == [
        "_acme.example.com.",
        "_acme.example.com",
    ]
