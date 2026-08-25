#!/usr/bin/env python3
"""Update only the reviewed browser client's exact redirect URI."""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

CLIENT_ID = "wai-web-app"
REDIRECT_URI = "https://workbench.ping.darkedges.com/oauth/callback"


def admin_origin(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("PF_ADMIN_URL must be a credential-free fixed HTTPS URL.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "/pf-admin-api/v1", "", ""))


base = admin_origin(os.getenv("PF_ADMIN_URL", "https://localhost:9999/pf-admin-api/v1"))
username = os.getenv("PF_ADMIN_USERNAME")
password = os.getenv("PF_ADMIN_PASSWORD")
if not username or not password:
    raise SystemExit("Set PF_ADMIN_USERNAME and PF_ADMIN_PASSWORD.")
if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
    raise SystemExit("Browser redirect update refuses disabled TLS validation.")

authorization = base64.b64encode(f"{username}:{password}".encode()).decode()
headers = {"Authorization": f"Basic {authorization}", "Accept": "application/json", "Content-Type": "application/json", "X-XSRF-Header": "PingFederate"}
context = ssl.create_default_context()


def request(method: str, body: dict | None = None) -> dict:
    path = f"/oauth/clients/{urllib.parse.quote(CLIENT_ID, safe='')}"
    req = urllib.request.Request(f"{base}{path}", headers=headers, data=None if body is None else json.dumps(body).encode(), method=method)
    try:
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"{method} browser client failed: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise SystemExit(f"{method} browser client failed: unable to reach PingFederate") from error


client = request("GET")
if client.get("clientId") != CLIENT_ID:
    raise SystemExit("PingFederate returned a conflicting browser client identity.")
redirects = client.get("redirectUris")
if not isinstance(redirects, list) or any(not isinstance(value, str) for value in redirects):
    raise SystemExit("PingFederate returned malformed browser redirect URIs.")
if redirects == [REDIRECT_URI]:
    print("PASS: exact public browser redirect is already configured.")
    raise SystemExit(0)
client["redirectUris"] = [REDIRECT_URI]
request("PUT", client)
verified = request("GET")
if verified.get("clientId") != CLIENT_ID or verified.get("redirectUris") != [REDIRECT_URI]:
    raise SystemExit("Browser redirect verification failed after update.")
print("PASS: updated only the exact wai-web-app browser redirect without printing credentials.")
