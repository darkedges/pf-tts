#!/usr/bin/env python3
"""Print safe identifiers for existing PingFederate authentication sources."""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request


def normalize_admin_url(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("PF_ADMIN_URL must be an HTTPS URL with a host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("PF_ADMIN_URL must not contain credentials, query parameters, or a fragment.")
    path = parsed.path.rstrip("/") or "/pf-admin-api/v1"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


admin_url = normalize_admin_url(os.getenv("PF_ADMIN_URL", "https://localhost:9999/pf-admin-api/v1"))
username = os.getenv("PF_ADMIN_USERNAME")
password = os.getenv("PF_ADMIN_PASSWORD")
if not username or not password:
    raise SystemExit("Set PF_ADMIN_USERNAME and PF_ADMIN_PASSWORD.")

context = ssl.create_default_context()
if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

authorization = base64.b64encode(f"{username}:{password}".encode()).decode()
headers = {"Authorization": f"Basic {authorization}", "Accept": "application/json", "X-XSRF-Header": "PingFederate"}


def request(path: str) -> dict:
    req = urllib.request.Request(f"{admin_url}{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            value = json.load(response)
            if not isinstance(value, dict):
                raise SystemExit(f"GET {path} returned malformed JSON.")
            return value
    except urllib.error.HTTPError as error:
        raise SystemExit(f"GET {path} failed: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise SystemExit(f"GET {path} failed: unable to reach PingFederate") from error


def safe_items(path: str, collection: str, id_keys: tuple[str, ...]) -> None:
    values = request(path).get("items")
    if not isinstance(values, list):
        raise SystemExit(f"GET {path} returned a malformed items collection.")
    print(f"{collection}:")
    for value in values:
        if not isinstance(value, dict):
            raise SystemExit(f"GET {path} returned a malformed item.")
        identifier = next((value.get(key) for key in id_keys if isinstance(value.get(key), str)), None)
        name = value.get("name") if isinstance(value.get("name"), str) else ""
        print(f"  id={identifier or '<missing>'} name={name or '<missing>'}")


safe_items("/idp/adapters", "IdP adapters", ("adapterId", "id"))
safe_items("/authenticationPolicyContracts", "Authentication policy contracts", ("contractId", "id"))
safe_items("/passwordCredentialValidators/descriptors", "Password credential validator descriptors", ("id",))

settings = request("/oauth/authServerSettings")
contract = settings.get("persistentGrantContract")
if not isinstance(contract, dict):
    raise SystemExit("OAuth server settings returned a malformed persistent-grant contract.")
attributes = contract.get("extendedAttributes")
if not isinstance(attributes, list):
    raise SystemExit("OAuth server settings returned malformed persistent-grant attributes.")
print("Persistent grant contract:")
print("  USER_KEY")
for attribute in attributes:
    if not isinstance(attribute, dict) or not isinstance(attribute.get("name"), str):
        raise SystemExit("OAuth server settings returned a malformed persistent-grant attribute.")
    print(f"  {attribute['name']}")

signing_key = request("/keyPairs/signing/wai-transaction-signing")
print("Transaction signing-key public fields:")
for key in sorted(signing_key):
    if key.lower() not in {"password", "privatekey", "private_key"}:
        print(f"  {key}")
