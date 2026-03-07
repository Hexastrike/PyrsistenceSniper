.PHONY: all test lint format typecheck fix cov

all: lint typecheck format fix test

test:
	poetry run pytest

lint:
	poetry run ruff check pyrsistencesniper/ tests/

format:
	poetry run ruff format pyrsistencesniper/ tests/

typecheck:
	poetry run mypy --strict pyrsistencesniper/

fix:
	poetry run ruff check --fix pyrsistencesniper/ tests/
	poetry run ruff format pyrsistencesniper/ tests/

cov:
	poetry run pytest --cov=pyrsistencesniper --cov-report=term-missing
