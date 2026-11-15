"""Renderer base class and the shared row shaping used by every format."""

from __future__ import annotations

import contextlib
import enum
import re
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import IO, Any

from pyrsistencesniper.core.models import (
    AnnotatedResult,
    ChangeEvidence,
    CheckFailure,
    Finding,
    HiveRecord,
    HiveStatus,
)

CORE_FIELDS: tuple[str, ...] = tuple(Finding.FIELDS.keys())

ERROR_LEVEL = "ERROR"

_READ_STATUSES = frozenset({HiveStatus.OPENED, HiveStatus.REPAIRED})

_HIVE_NOT_READ = (
    "Hive was not read. Checks reading it produced nothing, "
    "which is not the same as finding nothing."
)
_CHECK_FAILED = (
    "Check failed and produced nothing, which is not the same as finding nothing."
)
_ARTIFACT_LOST = "Could not be read in full, so findings from it may be missing."
_UNCOMMITTED = "Uncommitted transactions"
_HIVE_DIRTY = (
    "Values written to this hive shortly before collection "
    "may be missing from this report."
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")
_ILLEGAL_SPREADSHEET_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]")


# Without the escape handler, one artifact named outside the legacy Windows
# console codepage raises UnicodeEncodeError mid-render and every finding after
# it is lost, so an unprintable name could hide the rest of the report.
def _console_stream() -> IO[str]:
    """Return stdout set to escape characters its codepage cannot encode."""
    stream = sys.stdout
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None:
        with contextlib.suppress(ValueError, OSError):
            reconfigure(errors="backslashreplace")
    return stream


def label_for(field: str) -> str:
    """Return the column label, deriving one for enrichment keys."""
    label = Finding.FIELDS.get(field)
    if label is not None:
        return label
    if field.startswith("enrichment."):
        return " ".join(part.capitalize() for part in field.split(".")[1:])
    return field


# Findings carry attacker-controlled registry data: an unquoted leading formula
# trigger makes the report executable, and a control character the spreadsheet
# formats reject corrupts the whole workbook after a successful scan. Lone
# surrogates are replaced for the same reason and are worse: openpyxl accepts
# them, so the scan reports success and leaves a workbook nothing can open.
def sanitize_cell(value: object) -> str:
    """Quote formula triggers and replace rejected control characters."""
    text = _ILLEGAL_SPREADSHEET_CHARS.sub("�", str(value))
    stripped = text.lstrip()
    if stripped and stripped[0] in _FORMULA_PREFIXES:
        return f"'{text}"
    return text


def _integrity_row(level: str, hostname: str, **cells: str) -> dict[str, Any]:
    """Build one row with every findings column present and only known cells set."""
    row: dict[str, Any] = dict.fromkeys(CORE_FIELDS, "")
    row.update(
        cells,
        severity=level,
        hostname=hostname,
        change_evidence=ChangeEvidence.NOT_APPLICABLE.value,
    )
    return row


# Scan gaps are shaped into rows here instead of being modelled as findings. A
# finding passes allow rules and --min-severity, either of which could hide a
# gap, and it always states an access level, which a gap does not have.
def integrity_rows(
    inventory: tuple[HiveRecord, ...],
    failures: tuple[CheckFailure, ...],
    hostname: str = "",
) -> list[dict[str, Any]]:
    """Shape what the scan lost, then what it must caveat, into report rows."""
    rows = [
        _integrity_row(
            ERROR_LEVEL,
            hostname,
            path=record.label,
            value=record.outcome,
            description=_HIVE_NOT_READ,
        )
        for record in inventory
        if record.cost_checks
    ]
    rows.extend(
        _integrity_row(
            ERROR_LEVEL,
            hostname,
            path=failure.artifact,
            value=failure.error,
            check_id=failure.check_id,
            description=_ARTIFACT_LOST if failure.artifact else _CHECK_FAILED,
        )
        for failure in failures
    )
    rows.extend(
        _integrity_row(
            ERROR_LEVEL,
            hostname,
            path=record.label,
            value=_UNCOMMITTED,
            description=_HIVE_DIRTY,
        )
        for record in inventory
        if record.dirty and record.status in _READ_STATUSES
    )
    return rows


class OutputBase(ABC):
    """Base class that all output renderers must extend."""

    def render(
        self,
        results: list[AnnotatedResult],
        output: Path | IO[str] | None = None,
        *,
        inventory: tuple[HiveRecord, ...] = (),
        failures: tuple[CheckFailure, ...] = (),
        hostname: str = "",
    ) -> None:
        """Write results to a file path, open stream, or stdout."""
        if isinstance(output, Path):
            # Same escape handler as the console stream: a name the image
            # carries but UTF-8 cannot encode (a lone surrogate from a
            # non-UTF-8 filename) would otherwise raise mid-write and take
            # every later finding in the report with it.
            with output.open(
                "w", encoding="utf-8", errors="backslashreplace", **self._open_kwargs()
            ) as stream:
                self._write(
                    results,
                    stream,
                    inventory=inventory,
                    failures=failures,
                    hostname=hostname,
                )
        elif output is not None:
            self._write(
                results,
                output,
                inventory=inventory,
                failures=failures,
                hostname=hostname,
            )
        else:
            self._write(
                results,
                _console_stream(),
                inventory=inventory,
                failures=failures,
                hostname=hostname,
            )

    @abstractmethod
    def _write(
        self,
        results: list[AnnotatedResult],
        out: IO[str],
        *,
        inventory: tuple[HiveRecord, ...] = (),
        failures: tuple[CheckFailure, ...] = (),
        hostname: str = "",
    ) -> None: ...

    @staticmethod
    def unreadable_hives(
        inventory: tuple[HiveRecord, ...],
    ) -> tuple[HiveRecord, ...]:
        """Return the hives whose state silently removed checks from the scan."""
        return tuple(record for record in inventory if record.cost_checks)

    def _open_kwargs(self) -> dict[str, Any]:
        """Return extra keyword arguments for Path.open()."""
        return {}

    # Unresolved fields stay empty instead of collapsing to False: on a forensic
    # report, "not checked" must not read as "checked and absent".
    @staticmethod
    def result_to_dict(result: AnnotatedResult) -> dict[str, Any]:
        """Flatten an AnnotatedResult into one row dict."""
        finding, enrichments = result
        row: dict[str, Any] = {}
        for name in Finding.FIELDS:
            raw = getattr(finding, name)
            if isinstance(raw, enum.Enum):
                row[name] = raw.value
            elif isinstance(raw, tuple):
                row[name] = " | ".join(raw)
            elif raw is None:
                row[name] = ""
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

    # NOT_FOUND is claimed only when resolution ran and came back empty handed,
    # never when the target was left unresolved.
    @staticmethod
    def build_flags(row: dict[str, Any]) -> str:
        """Return the row's boolean flags as a comma-separated string."""
        flags: list[str] = []
        if row["is_lolbin"]:
            flags.append("LOLBin")
        if row["is_builtin"]:
            flags.append("Builtin")
        if row["is_in_os_directory"]:
            flags.append("OS_DIR")
        if row["exists"] is False:
            flags.append("NOT_FOUND")
        return ", ".join(flags)
