from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import IO, Any

from pyrsistencesniper.models.finding import AnnotatedResult


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
        d: dict[str, Any] = {
            "path": finding.path,
            "value": finding.value,
            "technique": finding.technique,
            "mitre_id": finding.mitre_id,
            "description": finding.description,
            "access_gained": finding.access_gained.value,
            "is_lolbin": finding.is_lolbin or False,
            "exists": finding.exists or False,
            "sha256": finding.sha256,
            "is_builtin": finding.is_builtin or False,
            "is_in_os_directory": finding.is_in_os_directory or False,
            "signer": finding.signer,
            "hostname": finding.hostname,
            "check_id": finding.check_id,
            "severity": finding.severity.value,
            "references": " | ".join(finding.references),
        }
        for enrichment in enrichments:
            for key, value in enrichment.data.items():
                d[f"enrichment.{enrichment.provider}.{key}"] = value
        return d

    @staticmethod
    def build_flags(d: dict[str, Any]) -> str:
        """Produce a comma-separated string of boolean flags from a result dict."""
        flags: list[str] = []
        if d["is_lolbin"]:
            flags.append("LOLBin")
        if d["is_builtin"]:
            flags.append("Builtin")
        if d["is_in_os_directory"]:
            flags.append("OS_DIR")
        if not d["exists"]:
            flags.append("NOT_FOUND")
        return ", ".join(flags)
