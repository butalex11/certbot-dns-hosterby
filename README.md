# certbot-dns-hosterby

Third-party Certbot DNS authenticator plugin for **hoster.by**.

## Status

This plugin has already been validated against the live `hoster.by` DNS API for the full TXT lifecycle used by ACME DNS-01:

- create TXT record
- update TXT record
- delete TXT record
- `certbot certonly --dry-run` for root + wildcard domains

## Features

- resolves the correct hoster.by DNS order for the requested domain
- creates `_acme-challenge` TXT records
- appends TXT values when a record already exists
- removes only the matching TXT value during cleanup
- deletes the TXT record entirely when no values remain
- supports either a ready access token or long-lived access key + secret key

## Confirmed hoster.by TXT format

The plugin uses the TXT format that was confirmed against the live API:

- `name` must be the full FQDN with a trailing dot, for example `_acme-challenge.example.com.`
- `records` must be an array of objects
- each TXT `content` value must include quotes inside the JSON string, for example `"token-value"`
- `disabled` must be `false`
- `ttl = 600` is accepted

## Credentials file

Create a credentials file, for example:

```ini
dns_hosterby_access_key = YOUR_ACCESS_KEY
dns_hosterby_secret_key = YOUR_SECRET_KEY
```

Or use a ready access token:

```ini
dns_hosterby_access_token = YOUR_ACCESS_TOKEN
```

Optional override:

```ini
dns_hosterby_api_url = https://serviceapi.hoster.by
```

Protect the file:

```bash
chmod 600 /etc/letsencrypt/hosterby.ini
```

## Installation

Install from the repository root:

```bash
python3 -m pip install .
```

Or build and install a wheel:

```bash
python3 -m pip install --upgrade build
python3 -m build
python3 -m pip install dist/certbot_dns_hosterby-0.1.0-py3-none-any.whl
```

## Check that Certbot sees the plugin

```bash
certbot plugins
```

You should see `dns-hosterby` in the plugin list.

## Example usage

```bash
certbot certonly \
  --authenticator dns-hosterby \
  --dns-hosterby-credentials /etc/letsencrypt/hosterby.ini \
  --dns-hosterby-propagation-seconds 30 \
  --dry-run \
  -d example.com \
  -d '*.example.com'
```

## Optional settings

```bash
--dns-hosterby-api-url https://serviceapi.hoster.by
--dns-hosterby-ttl 600
```

## Development

Run tests:

```bash
python3 -m pip install -e .[test]
pytest
```

Build the package:

```bash
python3 -m pip install --upgrade build
python3 -m build
```

## Planned next step

After publishing this package to PyPI, it can be proposed as a new provider for Nginx Proxy Manager by adding an entry to `backend/certbot/dns-plugins.json`.
