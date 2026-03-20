.PHONY: install dev lint format typecheck check hooks clean run-plan run-apply docker-build docker-plan docker-apply test test-up test-down test-parser

install:
	uv sync

dev:
	uv sync --group dev
	uv run prek install

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff check --fix src/ tests/
	uv run ruff format src/ tests/

typecheck:
	uv run ty check src/

check: lint typecheck

hooks:
	uv run prek run --all-files

run-plan:
	uv run python -m dbgov plan --file ./policies/*.yaml

run-apply:
	uv run python -m dbgov apply --file ./policies/*.yaml

docker-build:
	docker build -t dbgov:local .

docker-plan:
	docker run --rm \
		-e DBGOV_ENGINE \
		-e DBGOV_HOST \
		-e DBGOV_PORT \
		-e DBGOV_NAME \
		-e DBGOV_USER \
		-e DBGOV_PASSWORD \
		-v $(PWD)/policies:/app/policies \
		dbgov:local plan --file ./policies/*.yaml

docker-apply:
	docker run --rm \
		-e DBGOV_ENGINE \
		-e DBGOV_HOST \
		-e DBGOV_PORT \
		-e DBGOV_NAME \
		-e DBGOV_USER \
		-e DBGOV_PASSWORD \
		-v $(PWD)/policies:/app/policies \
		dbgov:local apply --file ./policies/*.yaml

test-up:
	docker compose up -d --wait

test-down:
	docker compose down -v

test: test-up
	uv run pytest tests/ -v
	$(MAKE) test-down

test-parser:
	uv run pytest tests/test_parser.py -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache
