#!/usr/bin/env python3
"""Run and cryptographically verify the live lab token exchange in memory."""

from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
JWT = "urn:ietf:params:oauth:token-type:jwt"
ACTOR_AUDIENCE = "urn:pingfederate:wai:token-exchange"


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Set {name} in the ignored local environment file.")
    return value


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


issuer = required("PF_TRANSACTION_ISSUER").rstrip("/")
parsed_issuer = urllib.parse.urlsplit(issuer)
if parsed_issuer.scheme != "https" or not parsed_issuer.netloc or parsed_issuer.username or parsed_issuer.password:
    raise SystemExit("PF_TRANSACTION_ISSUER must be an HTTPS origin without credentials.")


def validated_https_url(name: str, default: str) -> str:
    value = os.getenv(name, default)
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise SystemExit(f"{name} must be an HTTPS URL without credentials or fragment.")
    return value


token_endpoint = validated_https_url("PF_TOKEN_ENDPOINT", f"{issuer}/as/token.oauth2")
jwks_url = validated_https_url("PF_JWKS_URL", f"{issuer}/pf/JWKS")

context = ssl.create_default_context()
if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE


def post_form(form: dict[str, str], client_id: str, client_secret: str) -> tuple[int, dict]:
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    request = urllib.request.Request(
        token_endpoint,
        headers={
            "Authorization": f"Basic {basic}",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data=urllib.parse.urlencode(form).encode(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            payload = json.load(response)
            return response.status, payload if isinstance(payload, dict) else {}
    except urllib.error.HTTPError as error:
        try:
            payload = json.load(error)
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {}
        return error.code, payload if isinstance(payload, dict) else {}
    except urllib.error.URLError as error:
        raise SystemExit("PingFederate token endpoint is unreachable.") from error


subject_status, subject_payload = post_form(
    {
        "grant_type": "password",
        "username": os.getenv("TF_VAR_lab_user_name", "demo-user"),
        "password": required("TF_VAR_lab_user_password"),
        "scope": "mcp:invoke",
    },
    os.getenv("TF_VAR_lab_user_client_id", "wai-lab-user"),
    required("TF_VAR_lab_user_client_secret"),
)
subject_token = subject_payload.get("access_token")
if subject_status != 200 or not isinstance(subject_token, str):
    raise SystemExit(f"Authenticated subject-token request failed with HTTP {subject_status}.")

root = Path(__file__).resolve().parents[3]
probe = subprocess.run(
    ["docker", "compose", "-f", str(root / "deploy/spire/compose.yaml"), "--profile", "tools", "run", "--rm", "jwt-probe"],
    cwd=root,
    capture_output=True,
    text=True,
    timeout=45,
    check=False,
)
if probe.returncode != 0:
    detail = " ".join(probe.stderr.strip().split())[-500:]
    raise SystemExit(f"SPIRE JWT-SVID probe failed: {detail or 'no diagnostic'}")
lines = probe.stdout.splitlines()
marker = "token(spiffe://example.org/agent/demo):"
if marker not in lines or lines.index(marker) + 1 >= len(lines):
    raise SystemExit("SPIRE JWT-SVID probe returned an unexpected response.")
actor_token = lines[lines.index(marker) + 1].strip()
try:
    actor_header, actor_claims, _ = actor_token.split(".")
    actor_payload = json.loads(b64decode(actor_claims))
    actor_protected = json.loads(b64decode(actor_header))
except (ValueError, json.JSONDecodeError):
    raise SystemExit("SPIRE JWT-SVID probe returned malformed token metadata.")
actor_aud = actor_payload.get("aud", [])
if isinstance(actor_aud, str):
    actor_aud = [actor_aud]
if actor_payload.get("sub") != "spiffe://example.org/agent/demo" or ACTOR_AUDIENCE not in actor_aud:
    raise SystemExit("SPIRE JWT-SVID identity or audience mismatch.")
if actor_protected.get("alg") != "ES256" or not isinstance(actor_protected.get("kid"), str):
    raise SystemExit("SPIRE JWT-SVID algorithm or key ID mismatch.")

exchange_form = {
    "grant_type": GRANT,
    "subject_token": subject_token,
    "subject_token_type": ACCESS_TOKEN,
    "actor_token": actor_token,
    "actor_token_type": JWT,
    "requested_token_type": ACCESS_TOKEN,
    "audience": "mcp-gateway",
    "scope": "mcp:invoke",
}
exchange_client = os.getenv("TF_VAR_token_exchange_client_id", "wai-agent-token-exchange")
exchange_secret = required("TF_VAR_token_exchange_client_secret")

tampered = dict(exchange_form)
actor_parts = actor_token.split(".")
middle = len(actor_parts[1]) // 2
actor_parts[1] = actor_parts[1][:middle] + ("A" if actor_parts[1][middle] != "A" else "B") + actor_parts[1][middle + 1 :]
tampered["actor_token"] = ".".join(actor_parts)
bad_status, bad_payload = post_form(tampered, exchange_client, exchange_secret)
if bad_status < 400 or bad_status >= 500 or bad_payload.get("error") not in {"invalid_grant", "invalid_request"}:
    raise SystemExit(
        f"Tampered actor-token failure case returned HTTP {bad_status}, code={bad_payload.get('error', 'missing')}."
    )

exchange_status, exchange_payload = post_form(exchange_form, exchange_client, exchange_secret)
transaction_token = exchange_payload.get("access_token")
if exchange_status != 200 or not isinstance(transaction_token, str):
    error_code = exchange_payload.get("error", "unknown_error")
    raise SystemExit(f"Live token exchange failed with HTTP {exchange_status}, code={error_code}.")

try:
    encoded_header, encoded_claims, encoded_signature = transaction_token.split(".")
    header = json.loads(b64decode(encoded_header))
    claims = json.loads(b64decode(encoded_claims))
except (ValueError, json.JSONDecodeError):
    raise SystemExit("Transaction token is not a well-formed JWT.")
if header.get("alg") != "RS256" or header.get("typ") != "at+jwt":
    raise SystemExit("Transaction token algorithm or type is not allowlisted.")
kid = header.get("kid")
if kid != "wai-transaction-signing":
    raise SystemExit("Transaction token key ID is not the configured signing key.")

with urllib.request.urlopen(jwks_url, context=context, timeout=15) as response:
    jwks = json.load(response)
keys = [key for key in jwks.get("keys", []) if isinstance(key, dict) and key.get("kid") == kid and key.get("kty") == "RSA"]
if len(keys) != 1:
    raise SystemExit("JWKS did not contain exactly one matching RSA transaction key.")
key = keys[0]
try:
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(b64decode(key["e"]), "big"), int.from_bytes(b64decode(key["n"]), "big")
    ).public_key()
    public_key.verify(
        b64decode(encoded_signature),
        f"{encoded_header}.{encoded_claims}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
except (KeyError, ValueError):
    raise SystemExit("Transaction JWT signature verification failed.")

now = int(time.time())
expected = {
    "iss": issuer,
    "sub": os.getenv("TF_VAR_lab_user_name", "demo-user"),
    "agent_id": "urn:agent:demo",
    "workload_id": "spiffe://example.org/agent/demo",
    "transaction_purpose": "system.whoami",
    "scope": "mcp:invoke",
}
for name, value in expected.items():
    if claims.get(name) != value:
        raise SystemExit(f"Verified transaction claim {name!r} did not match trusted configuration.")
audience = claims.get("aud", [])
if isinstance(audience, str):
    audience = [audience]
if audience != ["urn:wai:mcp-gateway"]:
    raise SystemExit("Verified transaction audience did not exactly match urn:wai:mcp-gateway.")
if not isinstance(claims.get("iat"), (int, float)) or not isinstance(claims.get("exp"), (int, float)):
    raise SystemExit("Verified transaction token is missing numeric time claims.")
if claims["iat"] > now + 5 or claims["exp"] <= now or claims["exp"] - claims["iat"] != 20:
    raise SystemExit("Verified transaction token time bounds are invalid.")
for name in ("jti", "transaction_id", "agent_instance_id"):
    if not isinstance(claims.get(name), str) or not claims[name]:
        raise SystemExit(f"Verified transaction token is missing {name!r}.")

print("PASS: tampered actor rejected; live RFC 8693 exchange issued a verified 20-second transaction JWT with trusted user, agent, workload, audience, scope, and purpose bindings.")
