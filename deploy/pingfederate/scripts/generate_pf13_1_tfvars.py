#!/usr/bin/env python3
import json
import os
from pathlib import Path

root = Path(__file__).resolve().parents[1]
report_path = root / "discovered" / "wai-plugin-report.json"
if not report_path.exists():
    raise SystemExit("Run discover_pf_plugins.py first.")

report = json.loads(report_path.read_text())
server_version = str((report.get("serverVersion") or {}).get("version") or "")
if not server_version.startswith("13.1"):
    raise SystemExit(
        "Refusing to generate PingFederate 13.1 inputs from server version "
        f"{server_version or 'unknown'}. Point PF_ADMIN_URL at a reviewed 13.1 server "
        "and run discovery again."
    )

rec = report.get("recommended", {})
jwtp = rec.get("jwtTokenProcessor") or {}
oauthp = rec.get("oauthTokenProcessor") or {}
atm = rec.get("jwtAccessTokenManager") or {}

atm_field_names = {
    field.get("name")
    for field in ((atm.get("configDescriptor") or {}).get("fields") or [])
}
required_trusted_fields = {
    "Allowed Workload SPIFFE ID", "Logical Agent ID", "Transaction Purpose"
}
missing_trusted_fields = sorted(required_trusted_fields - atm_field_names)
if missing_trusted_fields:
    raise SystemExit(
        "Installed transaction ATM is stale; rebuild/install the WAI plugin and "
        "run discovery again. Missing: " + ", ".join(missing_trusted_fields)
    )

required = {
    "subject_token_processor_plugin_id": oauthp.get("id"),
    "actor_token_processor_plugin_id": jwtp.get("id"),
    "transaction_atm_plugin_id": atm.get("id"),
}
missing = [k for k,v in required.items() if not v]
if missing:
    raise SystemExit("Could not discover: " + ", ".join(missing))

expected_actor_class = "org.example.wai.spiffe.SpiffeJwtTokenProcessor"
if jwtp.get("className") != expected_actor_class:
    raise SystemExit(
        f"Refusing unreviewed actor processor {jwtp.get('className') or 'unknown'}; "
        f"expected {expected_actor_class}."
    )

expected_atm_class = "org.example.wai.transaction.ExactTtlJwtAccessTokenManager"
if atm.get("className") != expected_atm_class:
    raise SystemExit(
        f"Refusing unreviewed transaction ATM {atm.get('className') or 'unknown'}; "
        f"expected {expected_atm_class}."
    )

jwks_path = root / "discovered" / "spire-jwt.jwks.json"
if not jwks_path.exists():
    raise SystemExit("Run make spire-jwks before generating confirmed PingFederate inputs.")
jwks = json.loads(jwks_path.read_text(encoding="utf-8-sig"))
jwks_keys = jwks.get("keys") or []
if len(jwks_keys) != 1 or jwks_keys[0].get("use") != "sig" or jwks_keys[0].get("alg") != "ES256" or not jwks_keys[0].get("kid"):
    raise SystemExit("SPIRE JWKS must contain exactly one reviewed ES256 signing key with a key ID.")

transaction_issuer = os.getenv("PF_TRANSACTION_ISSUER", "").strip()
missing_env = [name for name, value in {
    "PF_TRANSACTION_ISSUER": transaction_issuer,
}.items() if not value]
if missing_env:
    raise SystemExit("Set non-secret local configuration references: " + ", ".join(missing_env))
if not transaction_issuer.startswith("https://"):
    raise SystemExit("PF_TRANSACTION_ISSUER must be an HTTPS issuer URL.")

out = root / "terraform" / "pf13_1.auto.tfvars.json"
payload = {
    **required,
    "actor_token_processor_configuration_fields": [
        {"name": "SPIRE JWKS", "value": json.dumps(jwks, separators=(",", ":"))},
        {"name": "Required Audience", "value": "urn:pingfederate:wai:token-exchange"},
        {"name": "Trust Domain", "value": "example.org"},
        {"name": "Maximum Lifetime Seconds", "value": "300"},
        {"name": "Allowed Clock Skew Seconds", "value": "5"},
    ],
    "transaction_atm_configuration_fields": [
        {"name": "Issuer", "value": transaction_issuer},
        {"name": "Audience", "value": "urn:wai:mcp-gateway"},
        {"name": "Token Lifetime Seconds", "value": "20"},
        {"name": "Allowed Workload SPIFFE ID", "value": "spiffe://example.org/agent/demo"},
        {"name": "Logical Agent ID", "value": "urn:agent:demo"},
        {"name": "Transaction Purpose", "value": "system.whoami"},
    ],
    "discovery_confirmed": True
}
out.write_text(json.dumps(payload, indent=2))
print(f"Wrote {out}")
print("Generated reviewed custom-plugin fields with discovery_confirmed=true.")
