"""CSV renderer with spreadsheet formula injection sanitizing."""

from __future__ import annotations

import csv
from typing import IO, Any

from pyrsistencesniper.core.models import AnnotatedResult, CheckFailure, HiveRecord
from pyrsistencesniper.output.base import (
    OutputBase,
    integrity_rows,
    label_for,
    sanitize_cell,
)


class CsvOutput(OutputBase):
    """Writes findings as CSV with formula-injection-safe cell values."""

    def _open_kwargs(self) -> dict[str, Any]:
        """Let the csv writer control line endings itself."""
        return {"newline": ""}

    def _write(
        self,
        results: list[AnnotatedResult],
        out: IO[str],
        *,
        inventory: tuple[HiveRecord, ...] = (),
        failures: tuple[CheckFailure, ...] = (),
        hostname: str = "",
    ) -> None:
        """Write one table: the scan's gaps first, then its findings."""
        # This format exists to be parsed, so a gap shares the findings' columns
        # and is told apart by its Severity cell, never by a second table shape.
        findings, fieldnames = self._flatten_results(results)
        rows = [*integrity_rows(inventory, failures, hostname), *findings]
        if not rows:
            return

        sanitized = [
            {field: sanitize_cell(value) for field, value in row.items()}
            for row in rows
        ]
        writer = csv.writer(out)
        writer.writerow([label_for(field) for field in fieldnames])
        for row in sanitized:
            writer.writerow([row.get(field, "") for field in fieldnames])
