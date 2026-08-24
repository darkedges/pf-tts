#!/usr/bin/env python3
"""Add the WAI transaction scope without replacing other OAuth server settings."""

from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_SCOPES = {"mcp:invoke", "mcp.system.whoami"}
SCOPE_NAME = os.getenv("PF_TRANSACTION_SCOPE", "mcp:invoke")
if SCOPE_NAME not in ALLOWED_SCOPES:
    raise SystemExit("PF_TRANSACTION_SCOPE is not an approved fixed transaction scope.")
SCOPE_DESCRIPTION = "Invoke an approved MCP target through the WAI transaction flow."


def normalize_admin_url(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("PF_ADMIN_URL must be an HTTPS URL with a host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit(
            "PF_ADMIN_URL must not contain credentials, query parameters, or a fragment."
        )
    path = parsed.path.rstrip("/") or "/pf-admin-api/v1"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


admin_url = normalize_admin_url(
    os.getenv("PF_ADMIN_URL", "https://localhost:9999/pf-admin-api/v1")
)
username = os.getenv("PF_ADMIN_USERNAME")
password = os.getenv("PF_ADMIN_PASSWORD")
if not username or not password:
    raise SystemExit("Set PF_ADMIN_USERNAME and PF_ADMIN_PASSWORD.")

context = ssl.create_default_context()
if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
	raise SystemExit("Scope provisioning refuses disabled TLS validation.")

authorization = base64.b64encode(f"{username}:{password}".encode()).decode()
headers = {
    "Authorization": f"Basic {authorization}",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-XSRF-Header": "PingFederate",
}


def request(method: str, path: str, body: dict | None = None) -> dict:
    encoded = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"{admin_url}{path}", headers=headers, data=encoded, method=method
    )
    try:
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        # Do not echo response bodies: a misconfigured server or intermediary
        # could reflect authorization material.
        raise SystemExit(f"{method} {path} failed: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise SystemExit(f"{method} {path} failed: unable to reach PingFederate") from error


settings = request("GET", "/oauth/authServerSettings")
scopes = settings.get("scopes")
if not isinstance(scopes, list):
    raise SystemExit("OAuth server settings returned a malformed scopes collection.")

matches = [scope for scope in scopes if scope.get("name") == SCOPE_NAME]
if len(matches) > 1:
    raise SystemExit(f"Refusing ambiguous duplicate OAuth scope {SCOPE_NAME!r}.")
if matches:
    print(f"OAuth scope {SCOPE_NAME!r} already exists.")
    raise SystemExit(0)

scopes.append(
    {"name": SCOPE_NAME, "description": SCOPE_DESCRIPTION, "dynamic": False}
)
settings["scopes"] = scopes
request("PUT", "/oauth/authServerSettings", settings)
print(f"Added OAuth scope {SCOPE_NAME!r} while preserving existing server settings.")
