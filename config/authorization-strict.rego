package wai.authz

import rego.v1

default allow := false

allow if {
	input.agent_id == "urn:agent:demo"
	input.workload_id == "spiffe://example.org/agent/demo"
	input.purpose == "system.whoami"
	input.target == "demo"
	input.tool == "system.whoami"
	count(input.scopes) == 1
	input.scopes[0] == "mcp.system.whoami"
}

allow if {
	input.agent_id == "urn:agent:web-app"
	input.workload_id == "spiffe://example.org/agent/web-app"
	input.purpose == "system.whoami"
	input.target == "demo"
	input.tool == "system.whoami"
	count(input.scopes) == 1
	input.scopes[0] == "mcp.system.whoami"
}
