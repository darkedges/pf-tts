#!/usr/bin/env python3
"""Obtain a short-lived lab subject token and exercise the container call chain."""

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


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"Set {name} in the ignored local environment file.")
    return value


root = Path(__file__).resolve().parents[2]
issuer = required("PF_TRANSACTION_ISSUER").rstrip("/")
ca_file = root / "deploy/pingfederate/generated/local-runtime-ca.pem"
if not ca_file.is_file():
    raise SystemExit("Run make pf-export-ca before the live application lab.")
context = ssl.create_default_context(cafile=str(ca_file))

client_id = os.getenv("TF_VAR_lab_user_client_id", "wai-lab-user")
client_secret = required("TF_VAR_lab_user_client_secret")
authorization = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
request = urllib.request.Request(
    f"{issuer}/as/token.oauth2",
    headers={
        "Authorization": f"Basic {authorization}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    },
    data=urllib.parse.urlencode(
        {
            "grant_type": "password",
            "username": os.getenv("TF_VAR_lab_user_name", "demo-user"),
            "password": required("TF_VAR_lab_user_password"),
            "scope": "mcp:invoke",
        }
    ).encode(),
    method="POST",
)
try:
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        payload = json.load(response)
except (urllib.error.URLError, json.JSONDecodeError) as error:
    raise SystemExit("Authenticated subject-token request failed.") from error
subject_token = payload.get("access_token")
if not isinstance(subject_token, str) or not subject_token:
    raise SystemExit("Authenticated subject-token response did not contain a token.")

compose = [
    "docker",
    "compose",
    "--env-file",
    ".env.local",
    "--profile",
    "local-lab",
    "-f",
    "deploy/docker/compose.yaml",
    "run",
    "--rm",
    "-e",
    "USER_ACCESS_TOKEN",
]
agent_audit_events: list[dict] = []


def agent(mode: str, expect_success: bool) -> None:
    environment = os.environ.copy()
    environment["USER_ACCESS_TOKEN"] = subject_token
    environment["AGENT_MODE"] = mode
    result = subprocess.run(
        [*compose, "demo-agent"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    output = result.stdout + result.stderr
    if subject_token in output or "Bearer eyJ" in output:
        raise SystemExit(f"Raw credential appeared in captured {mode} output.")
    if mode == "normal":
        for line in output.splitlines():
            candidate = line[line.find("{") :] if "{" in line else ""
            try:
                event = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                agent_audit_events.append(event)
    if (result.returncode == 0) != expect_success:
        diagnostic = " ".join(output.split())[-600:]
        for secret in (client_secret, required("TF_VAR_token_exchange_client_secret")):
            diagnostic = diagnostic.replace(secret, "[REDACTED]")
        raise SystemExit(f"Agent mode {mode} returned an unexpected result: {diagnostic or 'no diagnostic'}")


agent("normal", True)
agent("spoof-agent", False)
agent("wrong-audience", False)
agent("expired-token", False)
agent("unapproved-mcp", False)
agent("direct-to-api", False)

required_targets = {"demo-agent", "mcp-gateway", "demo-mcp-server", "demo-api"}
deadline = time.monotonic() + 10
while True:
    logs = subprocess.run(
        ["docker", "compose", "--env-file", ".env.local", "--profile", "app-only", "-f", "deploy/docker/compose.yaml", "logs", "--no-color"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if logs.returncode != 0:
        raise SystemExit("Could not collect application audit logs.")
    if subject_token in logs.stdout or subject_token in logs.stderr or "Bearer eyJ" in logs.stdout or "Bearer eyJ" in logs.stderr:
        raise SystemExit("Raw credential appeared in captured service logs.")

    targets_by_transaction: dict[str, set[str]] = {}
    service_events: list[dict] = []
    for line in logs.stdout.splitlines():
        candidate = line[line.find("{") :] if "{" in line else ""
        try:
            event = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        service_events.append(event)
    for event in [*agent_audit_events, *service_events]:
        transaction_id = event.get("transaction_id")
        target = event.get("target")
        if event.get("type") in {"transaction.exchange.succeeded", "transaction.verify.succeeded"} and isinstance(transaction_id, str) and isinstance(target, str):
            targets_by_transaction.setdefault(transaction_id, set()).add(target)
    if any(targets == required_targets for targets in targets_by_transaction.values()):
        break
    if time.monotonic() >= deadline:
        raise SystemExit("No single verified transaction ID was present in structured audit logs across agent, gateway, MCP server, and API.")
    time.sleep(0.25)

print("PASS: valid agent call reached the API with one transaction ID in structured hop logs; all identity, audience, route, expiry, direct-call, and token-leak failure cases passed.")
