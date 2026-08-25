#!/usr/bin/env python3
"""Fail-closed attestation of the isolated PingFederate 13.1 runtime.

Task 53 forbids planning or applying Terraform against the isolated logical TTS
until the reachable administrator API proves it is exactly PingFederate 13.1 and
exposes exactly the reviewed plugin classes. Every failure is reported by path
and status only: response bodies, credentials, and descriptor payloads are never
printed.
"""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

EXACT_VERSION = re.compile(r"^13\.1(\.\d+)*$")

REVIEWED_CLASSES = {
    "/idp/tokenProcessors/descriptors": (
        "org.example.wai.spiffe.SpiffeJwtTokenProcessor",
        "org.sourceid.wstrust.processor.oauth.BearerAccessTokenTokenProcessor",
    ),
    "/oauth/accessTokenManagers/descriptors": (
        "org.example.wai.transaction.ExactTtlJwtAccessTokenManager",
    ),
    "/idp/adapters/descriptors": (
        "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter",
    ),
}


def admin_base(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("PF_ADMIN_URL must be an HTTPS URL with a host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("PF_ADMIN_URL must not contain credentials, query parameters, or a fragment.")
    path = parsed.path.rstrip("/") or "/pf-admin-api/v1"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


BASE = admin_base(os.getenv("PF_ADMIN_URL", "https://localhost:9999/pf-admin-api/v1"))
USERNAME = os.getenv("PF_ADMIN_USERNAME")
PASSWORD = os.getenv("PF_ADMIN_PASSWORD")
if not USERNAME or not PASSWORD:
    raise SystemExit("Set PF_ADMIN_USERNAME and PF_ADMIN_PASSWORD.")
if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
    raise SystemExit("Runtime attestation refuses disabled TLS validation.")

CONTEXT = ssl.create_default_context()
HEADERS = {
    "Authorization": "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode(),
    "Accept": "application/json",
    "X-XSRF-Header": "PingFederate",
}


def get(path: str) -> dict:
    request = urllib.request.Request(BASE + path, headers=HEADERS, method="GET")
    try:
        with urllib.request.urlopen(request, context=CONTEXT, timeout=15) as response:
            if response.status != 200:
                raise SystemExit(f"GET {path} failed: HTTP {response.status}")
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"GET {path} failed: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise SystemExit(f"GET {path} failed: unable to reach the private administrator channel.") from error
    if not isinstance(payload, dict):
        raise SystemExit(f"GET {path} returned an unexpected document shape.")
    return payload


version = get("/version").get("version")
if not isinstance(version, str) or not EXACT_VERSION.match(version):
    raise SystemExit("Refusing to configure a runtime that does not report exact PingFederate 13.1.")

for path, reviewed_classes in REVIEWED_CLASSES.items():
    items = get(path).get("items")
    if not isinstance(items, list):
        raise SystemExit(f"GET {path} returned an unexpected descriptor collection.")
    installed = [item.get("className") for item in items if isinstance(item, dict)]
    for reviewed in reviewed_classes:
        matches = installed.count(reviewed)
        if matches == 0:
            raise SystemExit(f"Reviewed plugin class {reviewed} is not installed. Refusing to configure the runtime.")
        if matches > 1:
            raise SystemExit(f"Reviewed plugin class {reviewed} is ambiguous. Refusing to configure the runtime.")

print(f"PASS: attested exact PingFederate {version} and every reviewed plugin class over the private channel.")
sys.exit(0)
