"""CSV renderer with spreadsheet formula injection sanitizing."""

from __future__ import annotations

import csv
from typing import IO, Any

from pyrsistencesniper.core.models import ScanReport
from pyrsistencesniper.output.base import (
    CORE_FIELDS,
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

    def _write(self, report: ScanReport, out: IO[Any]) -> None:
        """Write one table: the scan's gaps first, then its findings."""
        # This format exists to be parsed, so a gap shares the findings' columns
        # and is told apart by its Severity cell, never by a second table shape.
        rows = [
            *integrity_rows(report),
            *self._flatten_results(report.findings),
        ]
        if not rows:
            return

        sanitized = [
            {field: sanitize_cell(value) for field, value in row.items()}
            for row in rows
        ]
        writer = csv.writer(out)
        writer.writerow([label_for(field) for field in CORE_FIELDS])
        for row in sanitized:
            writer.writerow([row.get(field, "") for field in CORE_FIELDS])
