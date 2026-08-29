.DEFAULT_GOAL := help
.PHONY: help install lint format-check type-check test render render-check secret-scan \
        schema-check poetry-lock-check check

# Every environment-specific value is an overridable knob with a documented
# default (AGENTS.md rule 14). Nothing below hardcodes a host, port or path.
ROOT     ?= .
RENDERED ?= deploy/rendered
CLI      ?= poetry run dotmac-observability --root $(ROOT)

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

render: ## Re-render the control-plane configuration and write it
	$(CLI) render --output $(RENDERED)

render-check: ## AGENTS.md rule 13 — committed bytes must equal a fresh render
	$(CLI) render --output $(RENDERED) --check

secret-scan: ## AGENTS.md rule 1 — no secret material in tracked files
	$(CLI) secret-scan

schema-check: ## Schema and cross-document gates over the inventory
	$(CLI) validate

check: poetry-lock-check lint format-check type-check secret-scan test ## Everything CI runs
	@echo "PR 1 ships no production inventory, so render-check and schema-check are"
	@echo "exercised against fixtures by the test suite. They join \`check\` in PR 3,"
	@echo "when inventory/ is populated — see docs/CONTROL_EXCEPTIONS.md."
