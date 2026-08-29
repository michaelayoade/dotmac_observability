.DEFAULT_GOAL := help
.PHONY: help install lint format-check type-check test render render-check secret-scan \
        private-scan schema-check poetry-lock-check check

# Every environment-specific value is an overridable knob with a documented
# default (AGENTS.md rule 14). Nothing below hardcodes a host, port or path.
ROOT      ?= .
# Since ADR-0006 the only tree this repository can render from a checkout is
# the SYNTHETIC reference fixture. A production render needs a private
# inventory and produces bytes carrying resolved endpoints and credential
# basenames, so it is neither committable nor reproducible by a public reader:
# it happens at promotion time and is recorded by digest. The four knobs below
# point the rendering targets at the fixture for that reason, and overriding
# them is how a promotion lane points them at real inputs.
FIXTURE   ?= tests/fixtures/reference
CONTRACTS ?= contracts
PRIVATE   ?= $(FIXTURE)/private/inventory.json
RENDERED  ?= $(FIXTURE)/rendered
CLI       ?= poetry run dotmac-observability --root $(ROOT)
RESOLVED  ?= poetry run dotmac-observability --root $(FIXTURE) --contracts $(CONTRACTS)

help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}'

install: ## Install pinned dependencies
	poetry install

poetry-lock-check: ## The committed lock must agree with pyproject; never regenerated here
	poetry check --lock

lint: ## Ruff lint
	poetry run ruff check .

format-check: ## Formatting is a gate, not a recipe line
	poetry run ruff format --check .

type-check: ## mypy strict
	poetry run mypy

test: ## Architecture, unit and mutation tests
	poetry run pytest

render: ## Re-render the reference configuration and write it
	$(RESOLVED) render --private-inventory $(PRIVATE) --output $(RENDERED)

render-check: ## AGENTS.md rule 13 — committed bytes must equal a fresh render
	$(RESOLVED) render --private-inventory $(PRIVATE) --output $(RENDERED) --check

secret-scan: ## AGENTS.md rule 1 — no secret VALUE in tracked files
	$(CLI) secret-scan

private-scan: ## AGENTS.md rule 18 — no resolved material in tracked files
	$(CLI) private-material-scan

schema-check: ## Schema, cross-document and resolution gates over the reference inventory
	$(RESOLVED) validate --private-inventory $(PRIVATE)

check: poetry-lock-check lint format-check type-check secret-scan private-scan schema-check \
       render-check test ## Everything CI runs
