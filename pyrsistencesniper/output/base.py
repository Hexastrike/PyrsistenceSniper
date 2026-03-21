from __future__ import annotations

import enum
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import IO, Any

from pyrsistencesniper.core.models import AnnotatedResult, Finding

CORE_FIELDS: tuple[str, ...] = tuple(Finding.FIELDS.keys())


class OutputBase(ABC):
    """Base class that all output renderers must extend."""

    def render(
        self,
        results: list[AnnotatedResult],
        output: Path | IO[str] | None = None,
    ) -> None:
        """Write results to a file path, open stream, or stdout."""
        if isinstance(output, Path):
            with output.open("w", encoding="utf-8", **self._open_kwargs()) as f:
                self._write(results, f)
        elif output is not None:
            self._write(results, output)
        else:
            self._write(results, sys.stdout)

    @abstractmethod
    def _write(self, results: list[AnnotatedResult], out: IO[str]) -> None: ...

    def _open_kwargs(self) -> dict[str, Any]:
        """Return additional kwargs passed to Path.open(). Override as needed."""
        return {}

    @staticmethod
    def result_to_dict(result: AnnotatedResult) -> dict[str, Any]:
        """Flatten an AnnotatedResult into a dict suitable for output rendering."""
        finding, enrichments = result
        row: dict[str, Any] = {}
        for name in Finding.FIELDS:
            raw = getattr(finding, name)
            if isinstance(raw, enum.Enum):
                row[name] = raw.value
            elif isinstance(raw, tuple):
                row[name] = " | ".join(raw)
            elif raw is None:
                row[name] = False
            else:
                row[name] = raw
        for enrichment in enrichments:
            for key, value in enrichment.data.items():
                row[f"enrichment.{enrichment.provider}.{key}"] = value
        return row

    @staticmethod
    def _flatten_results(
        results: list[AnnotatedResult],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Convert results to flat dicts; return rows and fieldnames."""
        rows: list[dict[str, Any]] = []
        enrichment_keys: set[str] = set()
        for result in results:
            row = OutputBase.result_to_dict(result)
            rows.append(row)
            for key in row:
                if key.startswith("enrichment."):
                    enrichment_keys.add(key)
        return rows, [*CORE_FIELDS, *sorted(enrichment_keys)]

    @staticmethod
    def build_flags(row: dict[str, Any]) -> str:
        """Produce a comma-separated string of boolean flags from a result dict."""
        flags: list[str] = []
        if row["is_lolbin"]:
            flags.append("LOLBin")
        if row["is_builtin"]:
            flags.append("Builtin")
        if row["is_in_os_directory"]:
            flags.append("OS_DIR")
        if not row["exists"]:
            flags.append("NOT_FOUND")
        return ", ".join(flags)
