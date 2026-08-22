#!/usr/bin/env python3
"""Probe known PingFederate JWKS endpoints and print only public key IDs."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

issuer = os.getenv("PF_TRANSACTION_ISSUER", "").rstrip("/")
parsed = urllib.parse.urlsplit(issuer)
if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
    raise SystemExit("PF_TRANSACTION_ISSUER must be an HTTPS origin without credentials.")

context = ssl.create_default_context()
if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

found = False
for path in ("/pf/JWKS", "/ext/oauth/jwks"):
    try:
        with urllib.request.urlopen(f"{issuer}{path}", context=context, timeout=15) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        print(f"{path}: HTTP {error.code}")
        continue
    except urllib.error.URLError:
        print(f"{path}: unreachable")
        continue
    keys = payload.get("keys") if isinstance(payload, dict) else None
    if not isinstance(keys, list):
        print(f"{path}: malformed JWKS")
        continue
    kids = sorted(key.get("kid") for key in keys if isinstance(key, dict) and isinstance(key.get("kid"), str))
    print(f"{path}: kids={kids}")
    if "wai-transaction-signing" in kids:
        found = True

if not found:
    raise SystemExit("Transaction signing key is not published by a standard PingFederate JWKS endpoint.")
