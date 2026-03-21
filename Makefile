.PHONY: all lint format fix typecheck test cov clean

all: fix typecheck test

lint:
	poetry run ruff check pyrsistencesniper/ tests/

format:
	poetry run ruff format pyrsistencesniper/ tests/

fix:
	poetry run ruff format pyrsistencesniper/ tests/
	poetry run ruff check --fix pyrsistencesniper/ tests/

typecheck:
	poetry run mypy --strict pyrsistencesniper/

test:
	poetry run pytest

cov:
	poetry run pytest --cov=pyrsistencesniper --cov-branch --cov-report=term-missing

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/
