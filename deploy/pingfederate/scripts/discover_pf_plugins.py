#!/usr/bin/env python3
"""
Discover PingFederate 13.1 plugin descriptors needed by the WAI lab.

Uses the PingFederate Admin API:
  GET /version
  GET /idp/tokenProcessors/descriptors
  GET /oauth/accessTokenManagers/descriptors
  GET /passwordCredentialValidators/descriptors

Authentication:
  PF_ADMIN_URL      e.g. https://localhost:9999/pf-admin-api/v1
  PF_ADMIN_USERNAME
  PF_ADMIN_PASSWORD

Optional:
  PF_ADMIN_INSECURE=true   lab only
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
from pathlib import Path

def normalize_admin_url(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit("PF_ADMIN_URL must be an HTTPS URL with a host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("PF_ADMIN_URL must not contain credentials, query parameters, or a fragment.")
    path = parsed.path.rstrip("/")
    if not path:
        path = "/pf-admin-api/v1"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

ADMIN_URL = normalize_admin_url(
    os.getenv("PF_ADMIN_URL", "https://localhost:9999/pf-admin-api/v1")
)
USERNAME = os.getenv("PF_ADMIN_USERNAME")
PASSWORD = os.getenv("PF_ADMIN_PASSWORD")
INSECURE = os.getenv("PF_ADMIN_INSECURE", "false").lower() == "true"

if not USERNAME or not PASSWORD:
    raise SystemExit("Set PF_ADMIN_USERNAME and PF_ADMIN_PASSWORD.")

print(f"Using PingFederate Admin API base: {ADMIN_URL}", file=sys.stderr)

ctx = ssl.create_default_context()
if INSECURE:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

auth = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()

def get(path: str):
    req = urllib.request.Request(
        f"{ADMIN_URL}{path}",
        headers={
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
            "X-XSRF-Header": "PingFederate",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        # Do not echo response bodies. An upstream error could reflect request
        # or authorization material.
        raise SystemExit(f"GET {path} failed: HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise SystemExit(f"GET {path} failed: unable to reach {ADMIN_URL}: {e.reason}") from e

def norm(s):
    return (s or "").lower().replace("-", " ")

def score(desc, terms):
    text = " ".join([
        str(desc.get("id", "")),
        str(desc.get("name", "")),
        str(desc.get("className", "")),
    ]).lower()
    return sum(10 if t in text else 0 for t in terms)

def select_actor_processor(items):
    reviewed_class = "org.example.wai.spiffe.SpiffeJwtTokenProcessor"
    reviewed = [item for item in items if item.get("className") == reviewed_class]
    if len(reviewed) > 1:
        raise SystemExit(f"Discovery is ambiguous: multiple {reviewed_class} descriptors were returned.")
    if reviewed:
        return reviewed[0]
    raise SystemExit(
        f"Required reviewed actor processor {reviewed_class} is not installed. "
        "Refusing to fall back to an issuer-based JWT processor."
    )

def select_transaction_atm(items):
    reviewed_class = "org.example.wai.transaction.ExactTtlJwtAccessTokenManager"
    reviewed = [item for item in items if item.get("className") == reviewed_class]
    if len(reviewed) > 1:
        raise SystemExit(f"Discovery is ambiguous: multiple {reviewed_class} descriptors were returned.")
    if reviewed:
        return reviewed[0]
    raise SystemExit(
        f"Required reviewed transaction ATM {reviewed_class} is not installed. "
        "Refusing to fall back to a minute-based access-token manager."
    )

def summarize_descriptor(d):
    cd = d.get("configDescriptor") or {}
    return {
        "id": d.get("id"),
        "name": d.get("name"),
        "className": d.get("className"),
        "supportsExtendedContract": d.get("supportsExtendedContract"),
        "attributeContract": d.get("attributeContract"),
        "tokenEndpointAttributeContract": d.get("tokenEndpointAttributeContract"),
        "configDescriptor": cd,
    }

out_dir = Path(__file__).resolve().parents[1] / "discovered"
out_dir.mkdir(parents=True, exist_ok=True)

version = get("/version")
token_processors = get("/idp/tokenProcessors/descriptors")
atms = get("/oauth/accessTokenManagers/descriptors")
pcvs = get("/passwordCredentialValidators/descriptors")

(out_dir/"version.json").write_text(json.dumps(version, indent=2))
(out_dir/"token-processor-descriptors.json").write_text(json.dumps(token_processors, indent=2))
(out_dir/"access-token-manager-descriptors.json").write_text(json.dumps(atms, indent=2))
(out_dir/"password-credential-validator-descriptors.json").write_text(json.dumps(pcvs, indent=2))

tp_items = token_processors.get("items", [])
atm_items = atms.get("items", [])

actor_processor = select_actor_processor(tp_items)
oauth_candidates = sorted(
    tp_items,
    key=lambda d: score(d, ["oauth", "access token"]),
    reverse=True,
)
transaction_atm = select_transaction_atm(atm_items)

report = {
    "serverVersion": version,
    "recommended": {
        "jwtTokenProcessor": summarize_descriptor(actor_processor),
        "oauthTokenProcessor": summarize_descriptor(oauth_candidates[0]) if oauth_candidates else None,
        "jwtAccessTokenManager": summarize_descriptor(transaction_atm),
    },
    "note": "Recommendations are heuristic. Review IDs and configDescriptor fields before applying Terraform.",
}
(out_dir/"wai-plugin-report.json").write_text(json.dumps(report, indent=2))

print(json.dumps(report, indent=2))
print(f"\nSaved discovery output to: {out_dir}")
