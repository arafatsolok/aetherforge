# =============================================================================
# AetherForge developer / operator Makefile
# =============================================================================
SHELL       := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

COMPOSE         ?= docker compose
COMPOSE_FULL    := $(COMPOSE) --profile full
PY              ?= python3.12
PROJECT         := aetherforge

# ---- Meta ------------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---- Environment -----------------------------------------------------------
.PHONY: env
env: ## Copy .env.example -> .env if missing
	@if [ ! -f .env ]; then cp .env.example .env; \
	  echo "[*] .env created — edit it and set passwords before 'make up'"; \
	else echo "[=] .env already exists"; fi

.PHONY: check-env
check-env:
	@test -f .env || (echo "[!] .env missing — run: make env"; exit 1)

# ---- Image lifecycle -------------------------------------------------------
.PHONY: build
build: check-env ## Build orchestrator + worker images
	$(COMPOSE) build orchestrator worker

.PHONY: build-all
build-all: check-env ## Build every image including tool containers
	$(COMPOSE_FULL) build

.PHONY: pull
pull: check-env ## Pull upstream images (postgres, redis, temporal, ...)
	$(COMPOSE) pull

# ---- Core stack ------------------------------------------------------------
.PHONY: up
up: check-env ## Start core stack (infra + orchestrator + worker)
	$(COMPOSE) up -d
	@$(MAKE) --no-print-directory status

.PHONY: up-full
up-full: check-env ## Start EVERYTHING (metasploit + openvas + wazuh)
	$(COMPOSE_FULL) up -d
	@$(MAKE) --no-print-directory status

.PHONY: down
down: ## Stop stack (keep volumes)
	$(COMPOSE_FULL) down

.PHONY: panic
panic: ## Emergency stop — kill every container immediately
	@echo "[!] PANIC — stopping every AetherForge container"
	-$(COMPOSE_FULL) kill
	-$(COMPOSE_FULL) down --remove-orphans
	@echo "[*] Halted. State volumes preserved."

.PHONY: nuke
nuke: ## DESTROY everything including volumes (requires CONFIRM=yes)
	@if [ "$${CONFIRM:-}" != "yes" ]; then \
	  echo "[!] Refusing to nuke volumes without CONFIRM=yes"; exit 1; fi
	$(COMPOSE_FULL) down -v --remove-orphans

# ---- Observability ---------------------------------------------------------
.PHONY: status
status: ## Show container status
	@echo
	$(COMPOSE_FULL) ps

.PHONY: logs
logs: ## Tail orchestrator + worker logs
	$(COMPOSE) logs -f --tail=200 orchestrator worker

.PHONY: logs-%
logs-%: ## Tail logs for a single service (e.g. make logs-temporal)
	$(COMPOSE_FULL) logs -f --tail=200 $*

.PHONY: top
top: ## Show container resource usage
	docker stats --no-stream

# ---- Database --------------------------------------------------------------
.PHONY: migrate
migrate: ## Run alembic upgrade head
	$(COMPOSE) exec orchestrator alembic -c migrations/alembic.ini upgrade head

.PHONY: migrate-revision
migrate-revision: ## Generate a new alembic migration (MSG="reason")
	$(COMPOSE) exec orchestrator alembic -c migrations/alembic.ini revision \
	  --autogenerate -m "$(MSG)"

.PHONY: seed
seed: ## Load baseline rules + knowledge base
	$(COMPOSE) exec orchestrator python -m scripts.seed_rules
	$(COMPOSE) exec orchestrator python -m scripts.seed_knowledge_base

.PHONY: psql
psql: ## Open psql against the running postgres
	$(COMPOSE) exec postgres psql -U "$${POSTGRES_USER:-aetherforge}" -d "$${POSTGRES_DB:-aetherforge}"

# ---- Dev ergonomics --------------------------------------------------------
.PHONY: shell
shell: ## Open a bash shell inside the orchestrator container
	$(COMPOSE) exec orchestrator /bin/bash

.PHONY: worker-shell
worker-shell: ## Open a bash shell inside the worker container
	$(COMPOSE) exec worker /bin/bash

.PHONY: fmt
fmt: ## ruff + black format (host-side, requires local venv)
	$(PY) -m ruff check --fix app tests scripts
	$(PY) -m black app tests scripts

.PHONY: lint
lint: ## ruff + mypy
	$(PY) -m ruff check app tests scripts
	$(PY) -m mypy app

.PHONY: test
test: ## Run pytest inside orchestrator container
	$(COMPOSE) exec orchestrator pytest -q

.PHONY: test-host
test-host: ## Run pytest on host venv (faster iteration)
	$(PY) -m pytest -q

.PHONY: test-fast
test-fast: ## Run only fast unit tests (excludes slow + integration)
	$(PY) -m pytest -q -m "unit and not slow"

.PHONY: test-integration
test-integration: ## Run integration tests against the live stack
	AETHERFORGE_TEST_BASE_URL=http://127.0.0.1:8002 $(PY) -m pytest -q -m integration

.PHONY: coverage
coverage: ## Run pytest with coverage report
	$(PY) -m pytest --cov=app --cov-report=term-missing --cov-report=html

.PHONY: e2e
e2e: ## End-to-end smoke: build → up → migrate → seed → scan → report → tear down
	./scripts/e2e_smoke.sh

# ---- Audit / inspection ----------------------------------------------------
.PHONY: audit
audit: ## Tail the audit log (commands generated by the rule engine)
	$(COMPOSE) exec orchestrator python -m scripts.audit_tail

.PHONY: rules-validate
rules-validate: ## Validate every rule YAML in rules/
	$(COMPOSE) exec orchestrator python -m scripts.validate_rules
