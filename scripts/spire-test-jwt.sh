#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$ROOT/deploy/spire/compose.yaml"

RESPONSE="$(docker compose -f "$COMPOSE" --profile tools run --rm jwt-probe 2>/dev/null)"
trap 'unset RESPONSE' EXIT

# The SPIRE CLI prints the credential. Keep it in memory only and emit safe
# verification metadata. This parses claims only as a probe assertion; no
# authorization decision is made from these unverified claim bytes.
printf '%s\n' "$RESPONSE" | python3 -c '
import base64, json, sys

lines = sys.stdin.read().splitlines()
header = "token(spiffe://example.org/agent/demo):"
try:
    index = lines.index(header)
    token = lines[index + 1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("unexpected JWT shape")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
except Exception:
    print("JWT-SVID probe returned an invalid response", file=sys.stderr)
    raise SystemExit(1)

expected_subject = "spiffe://example.org/agent/demo"
expected_audience = "urn:pingfederate:wai:token-exchange"
audiences = claims.get("aud", [])
if isinstance(audiences, str):
    audiences = [audiences]
if claims.get("sub") != expected_subject or expected_audience not in audiences:
    print("JWT-SVID probe identity or audience mismatch", file=sys.stderr)
    raise SystemExit(1)

print(f"JWT-SVID obtained: subject={expected_subject} audience={expected_audience}")
'
