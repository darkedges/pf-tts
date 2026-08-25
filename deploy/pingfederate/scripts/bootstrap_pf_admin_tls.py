#!/usr/bin/env python3
"""Install the reviewed Vault PKCS#12 Admin TLS key before Terraform connects."""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

KEY_ID = "wai-local-runtime-tls"


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"{name} is required.")
    return value


def admin_url() -> str:
    parsed = urllib.parse.urlsplit(required("PF_ADMIN_URL"))
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise SystemExit("PF_ADMIN_URL must be an HTTPS URL without credentials.")
    if parsed.query or parsed.fragment:
        raise SystemExit("PF_ADMIN_URL must not contain a query or fragment.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


BASE = admin_url()
AUTH = base64.b64encode(
    f"{required('PF_ADMIN_USERNAME')}:{required('PF_ADMIN_PASSWORD')}".encode()
).decode()
PFX = required("PF_BOOTSTRAP_SSL_FILE_DATA")
PFX_PASSWORD = required("PF_BOOTSTRAP_SSL_PASSWORD")
if len(PFX) > 100_000 or len(PFX_PASSWORD) > 4096:
    raise SystemExit("Bootstrap TLS material exceeds its reviewed bound.")

CONTEXT = ssl.create_default_context()
if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
    raise SystemExit("Admin TLS bootstrap refuses disabled certificate validation.")


def request(method: str, path: str, body: dict | None = None, allowed=(200,)) -> int:
    encoded = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=encoded,
        method=method,
        headers={
            "Authorization": f"Basic {AUTH}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-XSRF-Header": "PingFederate",
        },
    )
    try:
        with urllib.request.urlopen(req, context=CONTEXT, timeout=20) as response:
            if response.status not in allowed:
                raise SystemExit(f"{method} {path} returned unexpected HTTP status.")
            response.read(1)
            return response.status
    except urllib.error.HTTPError as error:
        if error.code in allowed:
            return error.code
        raise SystemExit(f"{method} {path} failed: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise SystemExit(f"{method} {path} failed: verified Admin API unavailable") from error


exists = request("GET", f"/keyPairs/sslServer/{KEY_ID}", allowed=(200, 404)) == 200
if not exists:
    request(
        "POST",
        "/keyPairs/sslServer",
        {"id": KEY_ID, "fileData": PFX, "password": PFX_PASSWORD},
        allowed=(200, 201),
    )

reference = {
    "id": KEY_ID,
    "location": f"https://localhost:9999/pf-admin-api/v1/keyPairs/sslServer/{KEY_ID}",
}
request(
    "PUT",
    "/keyPairs/sslServer/settings",
    {
        "runtimeServerCertRef": reference,
        "adminConsoleCertRef": reference,
        "activeRuntimeServerCerts": [reference],
        "activeAdminConsoleCerts": [reference],
    },
)
print("PASS: selected reviewed Vault-backed Admin TLS key without printing private material.")
