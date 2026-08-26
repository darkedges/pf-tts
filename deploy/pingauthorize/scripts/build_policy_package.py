#!/usr/bin/env python3
"""Author the WAI MCP authorization deployment package.

The package is a Symphonic policy graph. It was originally produced in a Policy
Editor that is not part of this repository, which makes hand-editing the JSON
the only way to change it -- and hand-wiring a graph of cross-referencing UUIDs
is exactly the kind of edit that goes subtly wrong.

This script is the authoring tool instead. It reads the committed package, adds
any reviewed rule that is missing, and writes it back. Every identifier it mints
is derived from the rule's own content, so running it twice produces the same
file and a rule can be reviewed by reading the tuple rather than the UUIDs.

It only ever adds a rule guarded by an AND over exact equality comparisons. It
cannot widen an existing rule, and it never removes one.

The package is integrity-protected: its final element is a DataStreamFooter
carrying a SHA-256 digest, and PingAuthorize refuses to start if the content does
not match it. Editing the graph therefore means recomputing that digest, which is
taken over the concatenated compact serialisation of every element before the
footer -- element bodies only, without the array's commas or brackets.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
import uuid

# A fixed namespace so identifiers are reproducible across machines and runs.
NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")

PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "policies" / "wai-mcp-authorization.deploymentpackage"

# The reviewed rules. Each is an exact tuple; a request matches only when every
# attribute is equal to its constant.
#
# The strict call chain synthesises the purpose from the signed route as
# "<target>:<tool>" (pkg/middleware/strict_identity.go), and carries the strict
# scope. The non-strict chain carries the bare tool name and mcp:invoke. Both
# are represented, so one package serves both.
RULES = [
    {
        "name": "Exact verified web agent tuple",
        "attributes": {
            "agent_id": "urn:agent:web-app",
            "workload_id": "spiffe://example.org/agent/web-app",
            "immediate_caller_id": "spiffe://example.org/agent/web-app",
            "purpose": "system.whoami",
            "scope": "mcp:invoke",
            "target": "demo",
            "tool": "system.whoami",
        },
    },
    {
        "name": "Exact verified strict web agent tuple",
        "attributes": {
            "agent_id": "urn:agent:web-app",
            "workload_id": "spiffe://example.org/agent/web-app",
            "immediate_caller_id": "spiffe://example.org/agent/web-app",
            "purpose": "demo:system.whoami",
            "scope": "mcp.system.whoami",
            "target": "demo",
            "tool": "system.whoami",
        },
    },
    {
        "name": "Exact verified strict demo agent tuple",
        "attributes": {
            "agent_id": "urn:agent:demo",
            "workload_id": "spiffe://example.org/agent/demo",
            "immediate_caller_id": "spiffe://example.org/agent/demo",
            "purpose": "demo:system.whoami",
            "scope": "mcp.system.whoami",
            "target": "demo",
            "tool": "system.whoami",
        },
    },
]


def identifier(*parts: str) -> str:
    return str(uuid.uuid5(NAMESPACE, "|".join(parts)))


FOOTER_CLASS = "DataStreamFooter"


def load(path: pathlib.Path) -> tuple[list, dict]:
    """Return the graph nodes and the integrity footer, separately."""
    nodes = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(nodes, list) or not nodes:
        raise SystemExit("the deployment package must be a non-empty JSON array")
    footer = nodes[-1]
    if not isinstance(footer, dict) or footer.get("@class") != FOOTER_CLASS:
        raise SystemExit("the deployment package does not end with an integrity footer")
    return nodes[:-1], footer


def digest(nodes: list) -> str:
    """The digest PingAuthorize verifies on startup.

    Taken over each element's compact serialisation concatenated together, with
    no separators and no enclosing array. Verified against the shipped package
    before this script was allowed to change it.
    """
    body = "".join(json.dumps(node, separators=(",", ":")) for node in nodes)
    return base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode()


def render(nodes: list, footer: dict) -> str:
    footer = dict(footer)
    footer["digest"] = digest(nodes)
    return json.dumps(nodes + [footer], separators=(",", ":"))


def index(nodes: list, cls: str) -> list:
    return [n for n in nodes if isinstance(n, dict) and n.get("class") == cls]


def attribute_nodes(nodes: list) -> dict[str, str]:
    """Map attribute name to the AttributeNode that reads it."""
    definitions = {n["id"]: n["name"] for n in index(nodes, "AttributeDefinition")}
    mapping = {}
    for node in index(nodes, "AttributeNode"):
        name = definitions.get(node.get("attributeDefinitionId"))
        if name:
            mapping[name] = node["id"]
    return mapping


def constant_nodes(nodes: list) -> dict[str, str]:
    return {n["constant"]: n["id"] for n in index(nodes, "ConstantNode")}


def policy_combiner(nodes: list) -> dict:
    """The CombinedDecisionNode that collects this policy's rules."""
    policies = [m for m in index(nodes, "Metadata") if m.get("originType") == "Policy"]
    if len(policies) != 1:
        raise SystemExit(f"expected exactly one policy, found {len(policies)}")
    origin = policies[0]["originId"]
    combiners = [n for n in index(nodes, "CombinedDecisionNode") if n.get("originLink") == origin]
    if len(combiners) != 1:
        raise SystemExit("expected exactly one decision combiner for the policy")
    return combiners[0]


def existing_rule_names(nodes: list) -> set[str]:
    return {m["name"] for m in index(nodes, "Metadata") if m.get("originType") == "Rule"}


def add_rule(nodes: list, rule: dict, guard: str) -> None:
    attributes = attribute_nodes(nodes)
    constants = constant_nodes(nodes)
    combiner = policy_combiner(nodes)

    missing = sorted(set(rule["attributes"]) - set(attributes))
    if missing:
        raise SystemExit(f"the package defines no attribute for {missing}; add a definition first")

    comparisons = []
    for name in sorted(rule["attributes"]):
        value = rule["attributes"][name]
        if value not in constants:
            constant_id = identifier("constant", value)
            nodes.append({"class": "ConstantNode", "id": constant_id, "constant": value})
            constants[value] = constant_id
        comparison_id = identifier("comparison", rule["name"], name, value)
        nodes.append({
            "class": "ComparisonNode",
            "id": comparison_id,
            "lhsInputNode": attributes[name],
            "rhsInputNode": constants[value],
            "operator": "EQUALS",
        })
        comparisons.append(comparison_id)

    logic_id = identifier("logic", rule["name"])
    nodes.append({"class": "BooleanLogicNode", "id": logic_id, "inputNodes": comparisons, "operator": "and"})

    origin_id = identifier("rule", rule["name"])
    nodes.append({
        "class": "Metadata",
        "originType": "Rule",
        "originId": origin_id,
        "name": rule["name"],
        "properties": {},
        "disabled": False,
        "repetitionSettings": None,
    })

    decision_id = identifier("decision", rule["name"])
    nodes.append({"class": "DecisionNode", "id": decision_id, "metadataId": origin_id, "effect": "PERMIT", "inputNode": logic_id})

    statement_id = identifier("statement", rule["name"])
    nodes.append({"class": "StatementNode", "id": statement_id, "inputNode": decision_id, "metadataId": origin_id, "statements": []})

    match_id = identifier("match", rule["name"])
    nodes.append({"class": "TargetMatchNode", "id": match_id, "inputNode": statement_id, "metadataId": origin_id, "targets": []})

    combiner["inputNodes"].append(match_id)
    combiner["inputNodeWeights"].append(100)
    _ = guard


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the package would change instead of writing it")
    arguments = parser.parse_args()

    nodes, footer = load(PACKAGE)
    if digest(nodes) != footer.get("digest"):
        raise SystemExit("the committed package's digest does not match its content; refusing to edit it")
    guards = index(nodes, "AlwaysTrueNode")
    if len(guards) != 1:
        raise SystemExit("expected exactly one always-true guard node")

    present = existing_rule_names(nodes)
    added = [rule["name"] for rule in RULES if rule["name"] not in present]
    for rule in RULES:
        if rule["name"] not in present:
            add_rule(nodes, rule, guards[0]["id"])

    unreviewed = sorted(present - {rule["name"] for rule in RULES})
    if unreviewed:
        raise SystemExit(f"the package contains unreviewed rules: {unreviewed}")

    rendered = render(nodes, footer)
    if rendered == PACKAGE.read_text(encoding="utf-8"):
        print(f"PASS: the package already contains exactly the {len(RULES)} reviewed rules.")
        return 0
    if arguments.check:
        print(f"FAIL: the package is out of step with the reviewed rules; missing {added}", file=sys.stderr)
        return 1
    PACKAGE.write_text(rendered, encoding="utf-8")
    print(f"Added {len(added)} reviewed rule(s): {added}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
