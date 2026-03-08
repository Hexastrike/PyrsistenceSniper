FROM python:3.12-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry

WORKDIR /app
COPY pyproject.toml ./
RUN poetry config virtualenvs.in-project true \
    && poetry install --only main --no-root --no-directory

COPY . .
RUN poetry install --only main

FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /app /app

ENTRYPOINT ["/app/.venv/bin/pyrsistencesniper"]
