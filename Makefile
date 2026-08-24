.PHONY: test helm-lint registry-login image-source-check images-push image-push-tts-adapter image-push-strict-mcp-gateway image-push-strict-demo-mcp-server image-push-strict-demo-api image-push-web-app images-inspect pf-profile-artifact pf-profile-artifact-push spire-up spire-register spire-jwt spire-jwks spire-down pf-profile pf-profile-export pf-clean-bootstrap pf-probe-txn-profile pf-test-txn-inner pf-test-tts-adapter pf-test-strict-call-chain pf-local-up pf-local-down pf-local-logs pf-discover pf-inspect-auth pf-verify-subject pf-probe-jwks pf-live-exchange pf-export-ca pf13-k8s-export-admin-ca pf-trust-local pf-generate-tfvars pf-ensure-scope pf-init pf-fmt pf-validate pf-plan pf-apply pa-local-up pa-local-down pa-local-logs pa-trust-local pa-export-runtime-ca web-tls app-config app-up lab-up lab-verify app-down platform-validate vault-import-pf13-privileged

REGISTRY_HOST ?= docker.io
REGISTRY_USER ?= darkedges
IMAGE_REGISTRY ?= $(REGISTRY_HOST)/$(REGISTRY_USER)
IMAGE_PREFIX ?= pf-tts-
IMAGE_TAG ?= $(shell git rev-parse --short=12 HEAD)
IMAGE_PLATFORMS ?= linux/amd64,linux/arm64
STRICT_IMAGES := tts-adapter strict-mcp-gateway strict-demo-mcp-server strict-demo-api
PF_PROFILE_ARTIFACT_IMAGE ?= $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)pingfederate-profile:$(IMAGE_TAG)

ifeq ($(OS),Windows_NT)
PYTHON_RUN ?= powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-python.ps1
else
PYTHON_RUN ?= python3
endif

test:
	go test ./...

helm-lint:
	helm lint deploy/helm/wai-strict -f deploy/helm/wai-strict/values-ci.yaml

registry-login:
ifeq ($(OS),Windows_NT)
	@pwsh -NoProfile -Command "if ([string]::IsNullOrWhiteSpace($$env:DOCKER_TOKEN)) { throw 'DOCKER_TOKEN is required.' }; $$env:DOCKER_TOKEN | docker login '$(REGISTRY_HOST)' -u '$(REGISTRY_USER)' --password-stdin"
else
	@test -n "$$DOCKER_TOKEN" || (echo 'DOCKER_TOKEN is required.' >&2; exit 1)
	@printf '%s' "$$DOCKER_TOKEN" | docker login "$(REGISTRY_HOST)" -u "$(REGISTRY_USER)" --password-stdin
endif

images-push: $(addprefix image-push-,$(STRICT_IMAGES))

image-source-check:
ifeq ($(OS),Windows_NT)
	@pwsh -NoProfile -Command "if (git status --porcelain) { throw 'Refusing to publish images from a dirty Git tree. Commit the reviewed source first.' }"
else
	@test -z "$$(git status --porcelain)" || (echo 'Refusing to publish images from a dirty Git tree. Commit the reviewed source first.' >&2; exit 1)
endif

image-push-tts-adapter image-push-strict-mcp-gateway image-push-strict-demo-mcp-server image-push-strict-demo-api image-push-web-app: image-source-check
	docker buildx build --platform $(IMAGE_PLATFORMS) --build-arg COMMAND=$(patsubst image-push-%,%,$@) --tag $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)$(patsubst image-push-%,%,$@):$(IMAGE_TAG) --push .

images-inspect:
	@$(foreach image,$(STRICT_IMAGES),docker buildx imagetools inspect $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)$(image):$(IMAGE_TAG)$(if $(filter $(image),$(lastword $(STRICT_IMAGES))),, &&) )

pf-profile-artifact:
	pwsh -NoProfile -File scripts/build-pingfederate-profile-artifact.ps1

pf-profile-artifact-push: image-source-check
	pwsh -NoProfile -File scripts/build-pingfederate-profile-artifact.ps1 -Push -ImageReference $(PF_PROFILE_ARTIFACT_IMAGE)

pf-runtime-image:
	pwsh -NoProfile -File scripts/build-pingfederate-runtime-image.ps1

pf-runtime-image-push: image-source-check
	pwsh -NoProfile -File scripts/build-pingfederate-runtime-image.ps1 -Push -ImageReference $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)pingfederate:$(IMAGE_TAG)

vault-import-local:
	pwsh -NoProfile -File scripts/import-env-local-to-vault.ps1

vault-import-pf13-privileged:
	pwsh -NoProfile -File scripts/import-pingfederate-13-1-bootstrap-to-vault.ps1 -IncludePrivilegedBootstrap

spire-up:
	bash scripts/spire-lab-up.sh

spire-register:
	bash scripts/spire-register.sh

spire-jwt:
	bash scripts/spire-test-jwt.sh

spire-jwks:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/spire-export-jwks.ps1

spire-down:
	bash scripts/spire-lab-down.sh


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

pf-profile:
	pwsh -NoProfile -File scripts/build-pingfederate-profile.ps1

pf-profile-export:
	pwsh -NoProfile -File scripts/export-pingfederate-profile.ps1

pf-clean-bootstrap:
	pwsh -NoProfile -File scripts/test-pingfederate-clean-bootstrap.ps1

pf-probe-txn-profile:
	pwsh -NoProfile -File scripts/test-pingfederate-clean-bootstrap.ps1 -ProbeTransactionTokens

pf-test-txn-inner:
	pwsh -NoProfile -File scripts/test-pingfederate-clean-bootstrap.ps1 -TestTransactionTokensInnerProfile

pf-test-tts-adapter:
	pwsh -NoProfile -File scripts/test-pingfederate-clean-bootstrap.ps1 -TestTTSAdapter

pf-test-strict-call-chain:
	pwsh -NoProfile -File scripts/test-pingfederate-clean-bootstrap.ps1 -TestStrictCallChain

pf-local-up: pf-profile
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

pf13-k8s-export-admin-ca:
	pwsh -NoProfile -File scripts/export-pf13-kubernetes-admin-ca.ps1

pf-trust-local:
	pwsh -NoProfile -File scripts/export-pf-local-ca.ps1 -Trust

pf-generate-tfvars:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/pingfederate/scripts/generate_pf13_1_tfvars.py

pf-ensure-scope:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/pingfederate/scripts/ensure_pf_scope.py

app-config:
	docker compose --env-file .env.local --profile app-only -f deploy/docker/compose.yaml config --quiet

web-tls:
	pwsh -NoProfile -File scripts/generate-web-local-tls.ps1 -Trust

pa-trust-local:
	pwsh -NoProfile -File scripts/export-pingauthorize-local-cert.ps1 -Trust

pa-export-runtime-ca:
	pwsh -NoProfile -File scripts/export-pingauthorize-runtime-cert.ps1

pa-local-up:
	pwsh -NoProfile -File scripts/ensure-wai-app-network.ps1
	docker compose --env-file .env.local -f deploy/pingauthorize/compose.yaml up -d

pa-local-down:
	docker compose --env-file .env.local -f deploy/pingauthorize/compose.yaml down

pa-local-logs:
	docker compose --env-file .env.local -f deploy/pingauthorize/compose.yaml logs -f pingauthorize

app-up:
	docker compose --env-file .env.local --profile app-only -f deploy/docker/compose.yaml up -d --build

lab-up:
	docker compose --env-file .env.local --profile local-lab -f deploy/docker/compose.yaml up -d --build audit-collector mcp-gateway demo-mcp-server demo-api web-app

lab-verify:
	$(PYTHON_RUN) -EnvFile .env.local -ScriptPath deploy/docker/run_live_lab.py

app-down:
	docker compose --env-file .env.local --profile app-only --profile local-lab -f deploy/docker/compose.yaml down

platform-validate:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-platforms.ps1
