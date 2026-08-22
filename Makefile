.PHONY: test spire-up spire-register spire-jwt spire-jwks spire-down pf-local-up pf-local-down pf-local-logs pf-discover pf-inspect-auth pf-verify-subject pf-probe-jwks pf-live-exchange pf-export-ca pf-generate-tfvars pf-ensure-scope pf-init pf-fmt pf-validate pf-plan pf-apply app-config app-up lab-up lab-verify app-down platform-validate

ifeq ($(OS),Windows_NT)
PYTHON_RUN ?= powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-python.ps1
else
PYTHON_RUN ?= python3
endif

test:
	go test ./...

spire-up:
	./scripts/spire-lab-up.sh

spire-register:
	./scripts/spire-register.sh

spire-jwt:
	./scripts/spire-test-jwt.sh

spire-jwks:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/spire-export-jwks.ps1

spire-down:
	./scripts/spire-lab-down.sh


pf-init:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-pf-terraform.ps1 init

pf-fmt:
	cd deploy/pingfederate/terraform && terraform fmt -recursive

pf-validate:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-pf-terraform.ps1 validate

pf-plan:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-pf-terraform.ps1 plan

pf-apply:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-pf-terraform.ps1 apply

pf-local-up:
	docker compose --env-file .env.local -f deploy/pingfederate/compose.yaml up -d

pf-local-down:
	docker compose --env-file .env.local -f deploy/pingfederate/compose.yaml down

pf-local-logs:
	docker compose --env-file .env.local -f deploy/pingfederate/compose.yaml logs -f pingfederate


pf-discover:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/pingfederate/scripts/discover_pf_plugins.py

pf-inspect-auth:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/pingfederate/scripts/inspect_pf_auth_sources.py

pf-verify-subject:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/pingfederate/scripts/verify_lab_subject_token.py

pf-probe-jwks:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/pingfederate/scripts/probe_pf_jwks.py

pf-live-exchange:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/pingfederate/scripts/verify_live_token_exchange.py

pf-export-ca:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/export-pf-local-ca.ps1

pf-generate-tfvars:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/pingfederate/scripts/generate_pf13_1_tfvars.py

pf-ensure-scope:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/pingfederate/scripts/ensure_pf_scope.py

app-config:
	docker compose --env-file .env.local --profile app-only -f deploy/docker/compose.yaml config --quiet

app-up:
	docker compose --env-file .env.local --profile app-only -f deploy/docker/compose.yaml up -d --build

lab-up:
	docker compose --env-file .env.local --profile local-lab -f deploy/docker/compose.yaml up -d --build

lab-verify:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/docker/run_live_lab.py

app-down:
	docker compose --env-file .env.local --profile app-only --profile local-lab -f deploy/docker/compose.yaml down

platform-validate:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-platforms.ps1
