#!/usr/bin/env python3
"""Probe draft-11 Transaction Tokens capabilities without exposing credentials."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
JWT = "urn:ietf:params:oauth:token-type:jwt"
TXN_TOKEN = "urn:ietf:params:oauth:token-type:txn_token"
ACTOR_AUDIENCE = "urn:pingfederate:wai:token-exchange"
MAXIMUM_RESPONSE_BYTES = 1 << 20
CONTAINER_PATTERN = re.compile(r"^wai-pf-clean-[0-9a-f]{16}$")
ERROR_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Set {name} in the ignored local environment file.")
    return value


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def decode_json(data: bytes) -> dict[str, object]:
    try:
        value = json.loads(data, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("response was not one unambiguous JSON object") from error
    if not isinstance(value, dict):
        raise ValueError("response was not one unambiguous JSON object")
    return value


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


container = required("PF_CAPABILITY_ISOLATED_CONTAINER")
if not CONTAINER_PATTERN.fullmatch(container):
    raise SystemExit("Capability probes require a random clean-bootstrap container name.")

token_endpoint = required("PF_TOKEN_ENDPOINT")
parsed_endpoint = urllib.parse.urlsplit(token_endpoint)
if (
    parsed_endpoint.scheme != "https"
    or parsed_endpoint.hostname != "localhost"
    or parsed_endpoint.port is None
    or parsed_endpoint.path != "/as/token.oauth2"
    or parsed_endpoint.username
    or parsed_endpoint.password
    or parsed_endpoint.query
    or parsed_endpoint.fragment
):
    raise SystemExit("Capability probes require the exact isolated localhost HTTPS token endpoint.")

binding = subprocess.run(
    ["docker", "port", container, "9031/tcp"],
    capture_output=True,
    text=True,
    timeout=10,
    check=False,
)
expected_binding = f"127.0.0.1:{parsed_endpoint.port}"
if binding.returncode != 0 or binding.stdout.strip() != expected_binding:
    raise SystemExit("Token endpoint does not match the isolated container runtime binding.")

if os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true":
    raise SystemExit("Capability probes prohibit disabled TLS verification.")
ca_input = Path(required("PF_CA_FILE"))
if ca_input.is_symlink():
    raise SystemExit("PF_CA_FILE must not be a symlink.")
ca_path = ca_input.resolve(strict=True)
if not ca_path.is_file() or ca_path.stat().st_size > 65536:
    raise SystemExit("PF_CA_FILE must be a regular PEM file no larger than 64 KiB.")
tls_context = ssl.create_default_context(cafile=str(ca_path))
opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=tls_context))


def bounded_body(response) -> bytes:  # noqa: ANN001
    body = response.read(MAXIMUM_RESPONSE_BYTES + 1)
    if len(body) > MAXIMUM_RESPONSE_BYTES:
        raise ValueError("response exceeded the capability probe limit")
    return body


def request_json(request: urllib.request.Request) -> tuple[int, dict[str, object]]:
    try:
        with opener.open(request, timeout=20) as response:
            return response.status, decode_json(bounded_body(response))
    except urllib.error.HTTPError as error:
        try:
            payload = decode_json(bounded_body(error))
        except ValueError:
            payload = {}
        return error.code, payload
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as error:
        raise SystemExit("PingFederate capability endpoint was unavailable over validated TLS.") from error


def post_form(form: dict[str, str], client_id: str, client_secret: str) -> tuple[int, dict[str, object]]:
    credential = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    request = urllib.request.Request(
        token_endpoint,
        headers={
            "Authorization": f"Basic {credential}",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data=urllib.parse.urlencode(form).encode(),
        method="POST",
    )
    return request_json(request)


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
if subject_status != 200 or not isinstance(subject_token, str) or not subject_token:
    raise SystemExit(f"Subject-token prerequisite failed with HTTP {subject_status}.")

root = Path(__file__).resolve().parents[3]
actor_probe = subprocess.run(
    [
        "docker",
        "compose",
        "-f",
        str(root / "deploy/spire/compose.yaml"),
        "--profile",
        "tools",
        "run",
        "--rm",
        "jwt-probe",
    ],
    cwd=root,
    capture_output=True,
    text=True,
    timeout=45,
    check=False,
)
if actor_probe.returncode != 0:
    raise SystemExit("SPIRE actor-token prerequisite failed without exposing subprocess output.")
lines = actor_probe.stdout.splitlines()
marker = "token(spiffe://example.org/agent/demo):"
if marker not in lines or lines.index(marker) + 1 >= len(lines):
    raise SystemExit("SPIRE actor-token prerequisite returned an ambiguous identity.")
actor_token = lines[lines.index(marker) + 1].strip()
try:
    actor_header_segment, actor_claim_segment, _ = actor_token.split(".")
    actor_header = decode_json(b64decode(actor_header_segment))
    actor_claims = decode_json(b64decode(actor_claim_segment))
except (ValueError, binascii.Error):
    raise SystemExit("SPIRE actor-token prerequisite returned malformed metadata.")
actor_audience = actor_claims.get("aud", [])
if isinstance(actor_audience, str):
    actor_audience = [actor_audience]
if (
    actor_claims.get("sub") != "spiffe://example.org/agent/demo"
    or ACTOR_AUDIENCE not in actor_audience
    or actor_header.get("alg") != "ES256"
    or not isinstance(actor_header.get("kid"), str)
    or not actor_header["kid"]
):
    raise SystemExit("SPIRE actor-token identity, audience, algorithm, or key ID was invalid.")

base_form = {
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


def safe_result(status: int, payload: dict[str, object]) -> dict[str, object]:
    error = payload.get("error")
    result: dict[str, object] = {
        "http_status": status,
        "oauth_error": error if isinstance(error, str) and ERROR_PATTERN.fullmatch(error) else None,
        "access_token_present": isinstance(payload.get("access_token"), str),
        "issued_token_type": payload.get("issued_token_type")
        if isinstance(payload.get("issued_token_type"), str)
        else None,
        "token_type": payload.get("token_type") if isinstance(payload.get("token_type"), str) else None,
        "refresh_token_present": "refresh_token" in payload,
        "expires_in_present": "expires_in" in payload,
        "scope_present": "scope" in payload,
    }
    token = payload.get("access_token")
    if isinstance(token, str):
        try:
            encoded_header, encoded_claims, encoded_signature = token.split(".")
            header = decode_json(b64decode(encoded_header))
            claims = decode_json(b64decode(encoded_claims))
            kid = header.get("kid")
            if header.get("alg") != "RS256" or not isinstance(kid, str) or not kid:
                raise ValueError("unexpected transaction signing metadata")
            jwks_url = token_endpoint.replace("/as/token.oauth2", "/pf/JWKS")
            jwks_request = urllib.request.Request(jwks_url, headers={"Accept": "application/json"})
            jwks_status, jwks = request_json(jwks_request)
            keys = [
                key
                for key in jwks.get("keys", [])
                if isinstance(key, dict) and key.get("kid") == kid and key.get("kty") == "RSA"
            ]
            if jwks_status != 200 or len(keys) != 1:
                raise ValueError("ambiguous transaction signing key")
            public_key = rsa.RSAPublicNumbers(
                int.from_bytes(b64decode(str(keys[0]["e"])), "big"),
                int.from_bytes(b64decode(str(keys[0]["n"])), "big"),
            ).public_key()
            public_key.verify(
                b64decode(encoded_signature),
                f"{encoded_header}.{encoded_claims}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            result.update(
                {
                    "jwt_signature_verified": True,
                    "jwt_typ": header.get("typ") if isinstance(header.get("typ"), str) else None,
                    "jwt_alg": header["alg"],
                    "jwt_kid": kid,
                    "claim_names": sorted(name for name in claims if isinstance(name, str)),
                }
            )
        except (KeyError, ValueError, binascii.Error):
            result["jwt_signature_verified"] = False
    return result


probes: list[tuple[str, dict[str, str]]] = []
probes.append(("current_profile_control", dict(base_form)))

missing_actor = dict(base_form)
del missing_actor["actor_token"]
del missing_actor["actor_token_type"]
probes.append(("missing_actor_rejected", missing_actor))

txn_existing_audience = dict(base_form)
txn_existing_audience["requested_token_type"] = TXN_TOKEN
probes.append(("txn_type_existing_audience", txn_existing_audience))

access_trust_domain = dict(base_form)
access_trust_domain["audience"] = "example.org"
probes.append(("access_type_trust_domain", access_trust_domain))

txn_trust_domain = dict(txn_existing_audience)
txn_trust_domain["audience"] = "example.org"
probes.append(("txn_type_trust_domain", txn_trust_domain))

context_current = dict(base_form)
context_current["request_context"] = json.dumps({"authn": "pwd"}, separators=(",", ":"))
context_current["request_details"] = json.dumps(
    {"target": "demo", "tool": "system.whoami"}, separators=(",", ":")
)
probes.append(("context_parameters_current_profile", context_current))

results: dict[str, object] = {
    "schema_version": 1,
    "draft": "draft-ietf-oauth-transaction-tokens-11",
    "image": "pingidentity/pingfederate:2606-13.1.0@sha256:3a74b4d40398202d7f32b029da4d59c73471bad952dec6225ca22f8857fa6be0",
    "isolated": True,
    "requester_authentication": "client_secret_basic_plus_spire_actor_jwt_svid",
    "probes": {},
}
for name, form in probes:
    status, payload = post_form(form, exchange_client, exchange_secret)
    results["probes"][name] = safe_result(status, payload)

control = results["probes"]["current_profile_control"]
if control.get("http_status") != 200 or control.get("jwt_signature_verified") is not True:
    raise SystemExit("Current-profile capability control did not return one verified JWT.")
actor_failure = results["probes"]["missing_actor_rejected"]
if actor_failure.get("http_status", 0) < 400 or actor_failure.get("http_status", 0) >= 500:
    raise SystemExit("Missing-actor failure control did not fail closed.")

print(json.dumps(results, indent=2, sort_keys=True))
