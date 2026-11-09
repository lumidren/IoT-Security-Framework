# IronMesh top-level developer entry points. Every target delegates to the component's own
# tooling (the same commands CI runs in .github/workflows/ci.yml).
#
#   make lint | test | cover | ci          all components (skip one with e.g. SKIP_CONSOLE=1)
#   make fuzz-smoke [FUZZ_SECONDS=60]      every cargo-fuzz target (nightly toolchain)
#   make conformance [DUT=agent-rs]        conformance suite, hermetic mode
#   make compose-up | compose-down | demo  local stack (deploy/docker) and the quickstart
#   make sbom                              CycloneDX SBOMs into dist/sbom/
#   make help

SHELL        := bash
.SHELLFLAGS  := -euo pipefail -c
.DEFAULT_GOAL := help

PYTHON       ?= python3
GO           ?= go
CARGO        ?= cargo
NPM          ?= npm
GO_SERVICES  := pki policy bridge
PY_SERVICES  := registry ota anomaly
WIRE         := libs/python/ironmesh-wire
AGENT        := device/agent-rs
ESP32_HOST   := device/esp32/host
FUZZ_CRATES  := $(AGENT) $(ESP32_HOST)
FUZZ_SECONDS ?= 60
DUT          ?= agent-rs
COMPOSE      := docker compose --project-directory deploy/docker -f deploy/docker/docker-compose.yml
DIST         := dist/sbom

.PHONY: help ci lint test cover fuzz-smoke conformance compose-up compose-down demo sbom \
        lint-go lint-python lint-rust lint-console lint-infra \
        test-go test-python test-rust test-console \
        cover-go cover-python cover-rust

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/' | sort | column -t -s "$$(printf '\t')"

ci: lint test cover ## everything CI gates on (except e2e, fuzz, conformance)

# --- lint ------------------------------------------------------------------------------------
lint: lint-go lint-python lint-rust lint-console lint-infra ## all linters

lint-go:
	@for svc in $(GO_SERVICES); do \
	  echo "== services/$$svc"; \
	  ( cd services/$$svc && test -z "$$(gofmt -l .)" && $(GO) vet ./... && golangci-lint run ./... ); \
	done

lint-python:
	@for dir in $(WIRE) $(addprefix services/,$(PY_SERVICES)); do \
	  echo "== $$dir"; \
	  ( cd $$dir && $(PYTHON) -m ruff check . && $(PYTHON) -m ruff format --check . && $(PYTHON) -m mypy --strict ); \
	done
	cd services/registry && $(PYTHON) -m bandit -q -c pyproject.toml -r app
	cd services/ota && $(PYTHON) -m bandit -q -c pyproject.toml -r src
	cd services/anomaly && $(PYTHON) -m bandit -q -c pyproject.toml -r src

lint-rust:
	cd $(AGENT) && $(CARGO) fmt --all --check && $(CARGO) clippy --all-targets --features dut-control -- -D warnings
	cd $(ESP32_HOST) && $(CARGO) fmt --all --check && $(CARGO) clippy --all-targets -- -D warnings
	$(PYTHON) device/esp32/tools/check_prod_config.py

lint-console:
ifndef SKIP_CONSOLE
	cd console && $(NPM) run lint && $(NPM) run typecheck && $(NPM) run format:check
endif

lint-infra:
	$(PYTHON) scripts/ci/check_env_contract.py
	$(PYTHON) scripts/ci/check_observability.py
	$(PYTHON) scripts/resolve_threat_refs.py --strict

# --- test ------------------------------------------------------------------------------------
test: test-go test-python test-rust test-console ## all unit and integration tests

test-go:
	@for svc in $(GO_SERVICES); do ( cd services/$$svc && $(GO) test ./... -race -count=1 ); done

test-python:
	@for dir in $(WIRE) $(addprefix services/,$(PY_SERVICES)); do ( cd $$dir && $(PYTHON) -m pytest ); done

test-rust:
	cd $(AGENT) && $(CARGO) test --locked && $(CARGO) test --locked --features dut-control
	cd $(ESP32_HOST) && $(CARGO) test --locked

test-console:
ifndef SKIP_CONSOLE
	cd console && $(NPM) test
endif

# --- coverage gates --------------------------------------------------------------------------
cover: cover-go cover-python cover-rust ## coverage gates (Go internal 90, Python 90 / wire 95, agent 85)

cover-go:
	@for svc in $(GO_SERVICES); do \
	  ( cd services/$$svc && $(GO) test ./... -race -covermode=atomic -coverprofile=coverage.out && \
	    $(PYTHON) ../../scripts/ci/go_coverage_gate.py coverage.out --min 90 --include /internal/ \
	      --exclude /internal/testutil/ --exclude /storetest/ ); \
	done

cover-python:
	cd $(WIRE) && $(PYTHON) -m pytest --cov=ironmesh_wire --cov-fail-under=95
	cd services/registry && $(PYTHON) -m pytest --cov=app --cov-fail-under=90
	cd services/ota && $(PYTHON) -m pytest --cov=ironmesh_ota --cov-fail-under=90
	cd services/anomaly && $(PYTHON) -m pytest --cov=ironmesh_anomaly --cov-fail-under=90

cover-rust:
	cd $(AGENT) && $(CARGO) llvm-cov --locked --features dut-control --fail-under-lines 85

# --- fuzzing and conformance -------------------------------------------------------------------
fuzz-smoke: ## every cargo-fuzz target for FUZZ_SECONDS (nightly)
	@for crate in $(FUZZ_CRATES); do \
	  ( cd $$crate && for t in $$($(CARGO) +nightly fuzz list); do \
	      mkdir -p fuzz/corpus/$$t; \
	      $(CARGO) +nightly fuzz run $$t fuzz/corpus/$$t -- -max_total_time=$(FUZZ_SECONDS) -max_len=16384; \
	    done ); \
	done

conformance: ## conformance suite, hermetic cloud (DUT=agent-rs|esp32-host)
	@if [ "$(DUT)" = agent-rs ]; then \
	  ( cd $(AGENT) && $(CARGO) build --locked --features dut-control --bin ironmesh-agent && $(CARGO) build --locked --release --bin ironmesh-agent ); \
	  args="--dut-bin $(AGENT)/target/debug/ironmesh-agent --release-bin $(AGENT)/target/release/ironmesh-agent"; \
	else \
	  ( cd $(ESP32_HOST) && $(CARGO) build --locked -p im-dut-shim ); \
	  args="--dut-bin $(ESP32_HOST)/target/debug/im-dut-shim"; \
	fi; \
	mkdir -p reports; \
	$(CARGO) run --locked --release --manifest-path conformance/Cargo.toml --bin ironmesh-conformance -- \
	  --dut "$(DUT)" $$args --junit "reports/conformance-$(DUT).xml"

# --- local stack -------------------------------------------------------------------------------
compose-up: ## start the local stack (deploy/docker; needs deploy/docker/.env)
	@test -f deploy/docker/.env || { echo "deploy/docker/.env missing: run 'make demo' or copy .env.example"; exit 1; }
	$(COMPOSE) up -d --build --wait

compose-down: ## stop the local stack (keeps volumes; add COMPOSE_DOWN_FLAGS=-v to wipe)
	$(COMPOSE) --profile tools down --remove-orphans $(COMPOSE_DOWN_FLAGS)

demo: ## 5-minute quickstart: stack, fleet, staged campaign, auto-quarantine
	scripts/demo/quickstart.sh

# --- SBOMs -------------------------------------------------------------------------------------
sbom: ## CycloneDX SBOMs of every source component into dist/sbom (see sbom/README.md)
	mkdir -p $(DIST)
	@for svc in $(GO_SERVICES); do cyclonedx-gomod mod -licenses -json -output $(DIST)/$$svc.cdx.json services/$$svc; done
	@for svc in $(PY_SERVICES); do \
	  $(PYTHON) -m venv .sbom-venv-$$svc && .sbom-venv-$$svc/bin/pip install -q ./$(WIRE) ./services/$$svc && \
	  cyclonedx-py environment --of JSON -o $(DIST)/$$svc.cdx.json .sbom-venv-$$svc/bin/python && rm -rf .sbom-venv-$$svc; \
	done
	$(PYTHON) -m venv .sbom-venv-wire && .sbom-venv-wire/bin/pip install -q ./$(WIRE) && \
	  cyclonedx-py environment --of JSON -o $(DIST)/ironmesh-wire.cdx.json .sbom-venv-wire/bin/python && rm -rf .sbom-venv-wire
	cd $(AGENT) && $(CARGO) cyclonedx --format json --all-features
	cd $(ESP32_HOST) && $(CARGO) cyclonedx --format json
	find $(AGENT) $(ESP32_HOST) -maxdepth 2 -name '*.cdx.json' -not -path '*/target/*' -exec mv {} $(DIST)/ \;
	cd console && npx --yes @cyclonedx/cyclonedx-npm@1.19.3 --omit dev --output-format JSON --output-file ../$(DIST)/console.cdx.json
