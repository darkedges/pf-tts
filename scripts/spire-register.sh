#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$ROOT/deploy/spire/compose.yaml"
GENERATED="$ROOT/deploy/spire/generated"

if [[ ! -s "$GENERATED/agent-id" ]]; then
  echo "Missing attested agent ID; run scripts/spire-lab-up.sh first." >&2
  exit 1
fi

PARENT="$(<"$GENERATED/agent-id")"
if [[ ! "$PARENT" =~ ^spiffe://example\.org/spire/agent/join_token/[[:xdigit:]-]+$ ]]; then
  echo "Refusing unexpected SPIRE agent parent ID." >&2
  exit 1
fi

create_entry() {
  local id="$1"
  local selector="$2"
  local existing

  existing="$(docker compose -f "$COMPOSE" exec -T spire-server \
    /opt/spire/bin/spire-server entry show -spiffeID "$id")"
  mapfile -t entry_ids < <(printf '%s\n' "$existing" | awk '/^Entry ID/ {print $4}')
  mapfile -t parent_ids < <(printf '%s\n' "$existing" | awk '/^Parent ID/ {print $4}')

  if [[ "${#entry_ids[@]}" -gt 1 ]] || [[ "${#entry_ids[@]}" -ne "${#parent_ids[@]}" ]]; then
    echo "Refusing ambiguous existing registration for $id." >&2
    exit 1
  fi
  if [[ "${#entry_ids[@]}" -eq 1 ]] && [[ "${parent_ids[0]}" == "$PARENT" ]]; then
      echo "Exists with current attested parent: $id"
      return
  fi
  if [[ "${#entry_ids[@]}" -eq 1 ]]; then
    echo "Replacing stale parent binding: $id"
    docker compose -f "$COMPOSE" exec -T spire-server \
      /opt/spire/bin/spire-server entry delete -entryID "${entry_ids[0]}"
  fi

  docker compose -f "$COMPOSE" exec -T spire-server \
    /opt/spire/bin/spire-server entry create \
    -parentID "$PARENT" \
    -spiffeID "$id" \
    -selector "$selector"
}

create_entry "spiffe://example.org/agent/demo" \
  "docker:label:wai.workload:demo-agent"

create_entry "spiffe://example.org/gateway/mcp" \
  "docker:label:wai.workload:mcp-gateway"

create_entry "spiffe://example.org/mcp/demo" \
  "docker:label:wai.workload:demo-mcp-server"

create_entry "spiffe://example.org/api/demo" \
  "docker:label:wai.workload:demo-api"

create_entry "spiffe://example.org/agent/web-app" \
  "docker:label:wai.workload:web-app"

create_entry "spiffe://example.org/audit/collector" \
  "docker:label:wai.workload:audit-collector"

echo "SPIRE workload entries registered."
