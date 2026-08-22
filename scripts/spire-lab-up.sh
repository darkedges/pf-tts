#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$ROOT/deploy/spire/compose.yaml"
GENERATED="$ROOT/deploy/spire/generated"

mkdir -p "$GENERATED"

docker compose -f "$COMPOSE" up -d spire-server

echo "Waiting for SPIRE Server..."
for _ in $(seq 1 30); do
  if docker compose -f "$COMPOSE" exec -T spire-server \
      /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

docker compose -f "$COMPOSE" exec -T spire-server \
  /opt/spire/bin/spire-server bundle show -format pem \
  > "$GENERATED/bundle.crt"

SPIRE_JOIN_TOKEN="$(
  docker compose -f "$COMPOSE" exec -T spire-server \
    /opt/spire/bin/spire-server token generate \
  | awk '/Token:/ {print $2}'
)"

if [[ -z "${SPIRE_JOIN_TOKEN}" ]]; then
  echo "Failed to generate SPIRE join token" >&2
  exit 1
fi

export SPIRE_JOIN_TOKEN
docker compose -f "$COMPOSE" up -d spire-agent

echo "Waiting for SPIRE Agent..."
for _ in $(seq 1 30); do
  if docker compose -f "$COMPOSE" exec -T spire-agent \
      /opt/spire/bin/spire-agent healthcheck \
      -socketPath /run/spire/sockets/agent.sock >/dev/null 2>&1; then
	mapfile -t AGENT_IDS < <(
	  docker compose -f "$COMPOSE" exec -T spire-server \
	    /opt/spire/bin/spire-server agent list \
	  | awk '/^SPIFFE ID/ {print $4}'
	)
	if [[ "${#AGENT_IDS[@]}" -ne 1 ]] ||
	   [[ ! "${AGENT_IDS[0]}" =~ ^spiffe://example\.org/spire/agent/join_token/[[:xdigit:]-]+$ ]]; then
	  echo "Expected exactly one unambiguous join-token agent identity." >&2
	  exit 1
	fi
	printf '%s\n' "${AGENT_IDS[0]}" > "$GENERATED/agent-id"
    echo "SPIRE lab is ready."
    exit 0
  fi
  sleep 1
done

echo "SPIRE Agent did not become healthy in time." >&2
docker compose -f "$COMPOSE" logs spire-agent >&2
exit 1
