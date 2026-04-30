.DEFAULT_GOAL := help

.PHONY: help install lint lint-fix fmt fmt-check typecheck test clean check update-rules

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install package and dev dependencies
	uv sync --group dev

lint: ## Run linter
	uv run ruff check src/ tests/

lint-fix: ## Run linter with auto-fix
	uv run ruff check --fix src/ tests/

fmt: ## Format code
	uv run ruff format src/ tests/

fmt-check: ## Check code formatting
	uv run ruff format --check src/ tests/

typecheck: ## Run type checker
	uv run pyright src/

test: ## Run tests
	uv run pytest

clean: ## Remove build artifacts and caches
	trash dist/ build/ .pytest_cache/ .ruff_cache/ 2>/dev/null || true
	find . -type d -name "__pycache__" -delete 2>/dev/null || true

check: lint fmt-check typecheck test ## Run all checks

update-rules: ## Launch Claude Code in plan mode preloaded with /update-rules
	claude --permission-mode plan -- "/update-rules"
