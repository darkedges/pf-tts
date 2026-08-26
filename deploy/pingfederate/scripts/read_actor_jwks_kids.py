#!/usr/bin/env python3
"""Print the SPIRE JWT authority key IDs the actor token processor trusts.

The processor holds a snapshot of SPIRE's JWT authorities. SPIRE rotates those,
publishing a prepared key hours before it signs with it, so comparing this list
against the live bundle shows whether the snapshot has fallen behind while there
is still time to act.

Key identifiers only are printed. No key material, credential, or response body
reaches the output.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

PROCESSOR_ID = "waiSpireJwtSvid"
FIELD = "SPIRE JWKS"


def admin_base(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("PF_ADMIN_URL must be an HTTPS URL with a host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("PF_ADMIN_URL must not contain credentials, a query, or a fragment.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "/pf-admin-api/v1", "", ""))


base = admin_base(os.getenv("PF_ADMIN_URL", "https://localhost:9999/pf-admin-api/v1"))
username = os.getenv("PF_ADMIN_USERNAME")
password = os.getenv("PF_ADMIN_PASSWORD")
if not username or not password:
    raise SystemExit("Set PF_ADMIN_USERNAME and PF_ADMIN_PASSWORD.")
if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
    raise SystemExit("Reading the actor processor refuses disabled TLS validation.")

request = urllib.request.Request(
    f"{base}/idp/tokenProcessors/{urllib.parse.quote(PROCESSOR_ID, safe='')}",
    headers={
        "Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode(),
        "Accept": "application/json",
        "X-XSRF-Header": "PingFederate",
    },
)
try:
    with urllib.request.urlopen(request, context=ssl.create_default_context(), timeout=15) as response:
        processor = json.load(response)
except urllib.error.HTTPError as error:
    raise SystemExit(f"Reading the actor processor failed: HTTP {error.code}") from error
except urllib.error.URLError:
    raise SystemExit("Reading the actor processor failed: the private administrator channel is unreachable.")

fields = (processor.get("configuration") or {}).get("fields")
if not isinstance(fields, list):
    raise SystemExit("The actor processor returned an unexpected configuration shape.")
for field in fields:
    if isinstance(field, dict) and field.get("name") == FIELD:
        try:
            keys = json.loads(field.get("value") or "{}").get("keys")
        except json.JSONDecodeError:
            raise SystemExit("The configured SPIRE JWKS is not valid JSON.")
        if not isinstance(keys, list):
            raise SystemExit("The configured SPIRE JWKS has no key collection.")
        for key in keys:
            if isinstance(key, dict) and key.get("kid"):
                print(key["kid"])
        sys.exit(0)
raise SystemExit(f"The actor processor has no {FIELD} field.")
