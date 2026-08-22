#!/usr/bin/env python3
"""Verify lab subject-token issuance without printing or persisting credentials."""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Set {name} in the ignored local environment file.")
    return value


issuer = required("PF_TRANSACTION_ISSUER").rstrip("/")
parsed = urllib.parse.urlsplit(issuer)
if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
    raise SystemExit("PF_TRANSACTION_ISSUER must be an HTTPS origin without credentials.")

client_id = os.getenv("TF_VAR_lab_user_client_id", "wai-lab-user")
client_secret = required("TF_VAR_lab_user_client_secret")
username = os.getenv("TF_VAR_lab_user_name", "demo-user")
password = required("TF_VAR_lab_user_password")

context = ssl.create_default_context()
if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
headers = {
    "Authorization": f"Basic {basic}",
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
}


def token_request(candidate_password: str) -> tuple[int, dict]:
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "username": username,
            "password": candidate_password,
            "scope": "mcp:invoke",
        }
    ).encode()
    request = urllib.request.Request(
        f"{issuer}/as/token.oauth2", headers=headers, data=body, method="POST"
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=15) as response:
            payload = json.load(response)
            return response.status, payload if isinstance(payload, dict) else {}
    except urllib.error.HTTPError as error:
        try:
            payload = json.load(error)
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {}
        return error.code, payload if isinstance(payload, dict) else {}
    except urllib.error.URLError as error:
        raise SystemExit("Token endpoint is unreachable.") from error


bad_status, bad_payload = token_request(password + "-intentionally-wrong")
if bad_status != 400 or bad_payload.get("error") != "invalid_grant":
    raise SystemExit("Wrong-password failure case did not return OAuth invalid_grant.")

status, payload = token_request(password)
if status != 200:
    raise SystemExit(f"Valid lab credential request failed with HTTP {status}.")
token = payload.get("access_token")
if not isinstance(token, str) or len(token) < 20:
    raise SystemExit("Token endpoint returned no usable access token.")
if str(payload.get("token_type", "")).lower() != "bearer":
    raise SystemExit("Token endpoint returned an unexpected token type.")
expires_in = payload.get("expires_in")
if not isinstance(expires_in, int) or expires_in <= 0 or expires_in > 600:
    raise SystemExit("Subject token lifetime is outside the lab safety bound.")
scope = payload.get("scope", "")
if scope and set(str(scope).split()) != {"mcp:invoke"}:
    raise SystemExit(f"Subject token scope does not exactly match mcp:invoke; got {scope!r}.")

print(f"PASS: wrong password rejected; authenticated subject token issued for {username!r} with lifetime {expires_in}s.")
