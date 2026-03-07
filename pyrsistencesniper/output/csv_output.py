from __future__ import annotations

import csv
from typing import IO, Any

from pyrsistencesniper.models.finding import AnnotatedResult
from pyrsistencesniper.output.base import OutputBase

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _sanitize_cell(value: object) -> str:
    """Escape formula-trigger prefixes to prevent injection."""
    s = str(value)
    stripped = s.lstrip()
    if stripped and stripped[0] in _FORMULA_PREFIXES:
        return f"'{s}"
    return s


class CsvOutput(OutputBase):
    """Writes findings as CSV with formula-injection-safe cell values."""

    def _open_kwargs(self) -> dict[str, Any]:
        return {"newline": ""}

    def _write(self, results: list[AnnotatedResult], out: IO[str]) -> None:
        if not results:
            return

        fieldnames = [
            "path",
            "value",
            "technique",
            "mitre_id",
            "description",
            "access_gained",
            "is_lolbin",
            "exists",
            "sha256",
            "is_builtin",
            "is_in_os_directory",
            "signer",
            "hostname",
            "check_id",
            "references",
        ]
        # Gather dynamic enrichment column names across all rows
        all_keys: set[str] = set()
        rows: list[dict[str, str]] = []
        for result in results:
            d = self.result_to_dict(result)
            sanitized = {k: _sanitize_cell(v) for k, v in d.items()}
            rows.append(sanitized)
            for key in d:
                if key.startswith("enrichment."):
                    all_keys.add(key)

        fieldnames.extend(sorted(all_keys))
        writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
