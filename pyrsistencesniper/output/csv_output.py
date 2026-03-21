from __future__ import annotations

import csv
from typing import IO, Any

from pyrsistencesniper.core.models import AnnotatedResult, Finding
from pyrsistencesniper.output.base import OutputBase

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _sanitize_cell(value: object) -> str:
    """Escape formula-trigger prefixes to prevent injection."""
    text = str(value)
    stripped = text.lstrip()
    if stripped and stripped[0] in _FORMULA_PREFIXES:
        return f"'{text}"
    return text


class CsvOutput(OutputBase):
    """Writes findings as CSV with formula-injection-safe cell values."""

    def _open_kwargs(self) -> dict[str, Any]:
        return {"newline": ""}

    def _write(self, results: list[AnnotatedResult], out: IO[str]) -> None:
        if not results:
            return

        rows, fieldnames = self._flatten_results(results)
        labels = [Finding.FIELDS.get(f, f) for f in fieldnames]
        sanitized = [{k: _sanitize_cell(v) for k, v in row.items()} for row in rows]
        writer = csv.writer(out)
        writer.writerow(labels)
        for row in sanitized:
            writer.writerow([row.get(f, "") for f in fieldnames])
