"""Tests for OutputBase helpers: result_to_dict and build_flags."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Any

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckFailure,
    Finding,
    HiveRecord,
    HiveStatus,
)
from pyrsistencesniper.output.base import (
    CORE_FIELDS,
    OutputBase,
    _console_stream,
    integrity_rows,
    sanitize_cell,
)


def _make_finding(**kwargs: object) -> Finding:
    """Build a Finding with all required fields set; kwargs override the defaults."""
    defaults = {
        "path": "HKLM\\Run",
        "value": "test.exe",
        "technique": "Test",
        "mitre_id": "T0000",
        "description": "d",
        "access_gained": AccessLevel.SYSTEM,
        "hostname": "HOST",
        "check_id": "test_check",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def _row(**kwargs: object) -> dict[str, Any]:
    """Build the report row a renderer would emit for one Finding."""
    return OutputBase.result_to_dict(_make_finding(**kwargs))


def test_result_to_dict_enum_to_value() -> None:
    """A report carries the enum's value, never the AccessLevel.USER repr."""
    assert _row(access_gained=AccessLevel.USER)["access_gained"] == "USER"


def test_result_to_dict_tuple_joined() -> None:
    """Multi-valued fields flatten into one cell so every format can carry them."""
    assert _row(references=("ref1", "ref2"))["references"] == "ref1 | ref2"


def test_result_to_dict_unresolved_field_renders_empty() -> None:
    """An unresolved field renders empty so it cannot read as a checked negative."""
    assert _row(is_lolbin=None)["is_lolbin"] == ""


def test_result_to_dict_resolved_false_stays_false() -> None:
    """A field the resolver actually determined to be false is preserved."""
    assert _row(is_lolbin=False)["is_lolbin"] is False


def test_build_flags_omits_not_found_when_existence_unknown() -> None:
    """An unresolved target is not claimed to be missing."""
    assert "NOT_FOUND" not in OutputBase.build_flags(_row(exists=None))


def test_build_flags_reports_not_found_when_resolution_missed() -> None:
    """A target the resolver looked for and did not find is flagged NOT_FOUND."""
    assert "NOT_FOUND" in OutputBase.build_flags(_row(exists=False))


def test_build_flags_lolbin() -> None:
    """A lone true flag renders as its bare name, with no separator debris."""
    row = _row(is_lolbin=True, is_builtin=False, is_in_os_directory=False, exists=True)
    assert OutputBase.build_flags(row) == "LOLBin"


def test_build_flags_not_found() -> None:
    """A resolved absence surfaces in the flag column an analyst reads."""
    row = _row(
        is_lolbin=False, is_builtin=False, is_in_os_directory=False, exists=False
    )
    assert "NOT_FOUND" in OutputBase.build_flags(row)


def test_build_flags_multiple() -> None:
    """Flags accumulate rather than the first true one winning the column."""
    row = _row(is_lolbin=True, is_builtin=True, is_in_os_directory=True, exists=True)
    flags = OutputBase.build_flags(row)
    assert "LOLBin" in flags
    assert "Builtin" in flags
    assert "OS_DIR" in flags


def test_build_flags_empty() -> None:
    """A plain, present, non-OS binary produces no flags at all."""
    row = _row(is_lolbin=False, is_builtin=False, is_in_os_directory=False, exists=True)
    assert OutputBase.build_flags(row) == ""


def test_console_stream_escapes_characters_the_codepage_cannot_encode() -> None:
    """A name outside the console codepage must not abort the report part-written."""
    # An attacker names the payload, so an unencodable artifact is reachable on
    # purpose: unescaped it would take every later finding down with it.
    legacy = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    original = sys.stdout
    sys.stdout = legacy
    try:
        stream = _console_stream()
        stream.write("C:\\Users\\hx\\\u666e\u901a.exe\n")
        stream.flush()
    finally:
        sys.stdout = original

    written = legacy.buffer.getvalue().decode("cp1252")
    assert "\\u666e" in written
    assert "\\u901a" in written


# A non-UTF-8 filename in the image reaches a finding as a lone surrogate via
# surrogateescape, which is routine when a Windows image is mounted on Linux.
_SURROGATE_NAME = "evil" + chr(0xDCFF) + ".exe"


def test_file_report_survives_an_unencodable_name(tmp_path: Path) -> None:
    """One name UTF-8 cannot encode must not destroy the whole report file."""

    class _Renderer(OutputBase):
        def _write(
            self, results, out, *, inventory=(), failures=(), hostname=""
        ) -> None:
            out.write(_SURROGATE_NAME + "\n")
            out.write("the finding after it\n")

    target = tmp_path / "report.txt"
    _Renderer().render([], output=target)

    written = target.read_text(encoding="utf-8")
    assert "the finding after it" in written, "later findings must survive"
    assert "\\udcff" in written, "the name is escaped rather than dropped"


def test_sanitize_cell_replaces_a_lone_surrogate() -> None:
    """openpyxl accepts a surrogate and then writes a workbook nothing can open."""
    cleaned = sanitize_cell(_SURROGATE_NAME)
    assert chr(0xDCFF) not in cleaned
    assert cleaned.startswith("evil")


def test_integrity_rows_are_empty_for_a_clean_scan() -> None:
    """A scan that read everything adds no row about itself."""
    inventory = (HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED),)

    assert integrity_rows(inventory, ()) == []


def test_integrity_row_carries_every_findings_column() -> None:
    """A gap row has the findings' exact columns, so no format needs a second shape."""
    (row,) = integrity_rows(
        (), (CheckFailure(check_id="run_keys", error="OSError: bad cell"),), "HOST"
    )

    assert tuple(row) == CORE_FIELDS
    assert row["severity"] == "ERROR"
    assert row["hostname"] == "HOST"


def test_integrity_row_claims_nothing_a_gap_cannot_know() -> None:
    """A gap gained no access and names no binary, so those cells stay empty."""
    (row,) = integrity_rows(
        (), (CheckFailure(check_id="run_keys", error="OSError: bad cell"),)
    )

    assert row["access_gained"] == ""
    assert row["technique"] == ""
    assert row["exists"] == ""
    assert row["change_evidence"] == "NOT_APPLICABLE"


def test_integrity_row_splits_a_lost_artifact_from_its_check() -> None:
    """The check and the file it lost land in their own columns."""
    (row,) = integrity_rows(
        (),
        (
            CheckFailure(
                check_id="scheduled_tasks", artifact=r"C:\Tasks\Bad", error="boom"
            ),
        ),
    )

    assert row["check_id"] == "scheduled_tasks"
    assert row["path"] == r"C:\Tasks\Bad"
    assert row["value"] == "boom"


def test_integrity_row_names_a_user_hive_with_its_owner() -> None:
    """Two users' NTUSER.DAT hives must not collapse into one indistinct row."""
    hive = HiveRecord(
        name="NTUSER.DAT",
        owner="alice",
        status=HiveStatus.OPEN_FAILED,
        error="OSError: bad hive",
    )

    (row,) = integrity_rows((hive,), ())

    assert row["path"] == "NTUSER.DAT [alice]"
    assert row["value"] == "OPEN_FAILED: OSError: bad hive"


def test_integrity_row_for_an_uncollected_hive_states_the_status_alone() -> None:
    """A hive the image never held has no error text to invent."""
    hive = HiveRecord(name="SYSTEM", status=HiveStatus.NOT_COLLECTED)

    (row,) = integrity_rows((hive,), ())

    assert row["value"] == "NOT_COLLECTED"


def test_integrity_rows_report_a_dirty_hive_that_was_read() -> None:
    """Uncommitted transactions get a row of their own, naming the hive."""
    hive = HiveRecord(name="SOFTWARE", status=HiveStatus.REPAIRED, dirty=True)

    (row,) = integrity_rows((hive,), ())

    assert row["severity"] == "ERROR"
    assert row["path"] == "SOFTWARE"
    assert row["value"] == "Uncommitted transactions"


def test_integrity_rows_ignore_the_dirty_flag_of_a_hive_that_never_opened() -> None:
    """An unread hive is reported once, as lost, never also as merely dirty."""
    hive = HiveRecord(name="SYSTEM", status=HiveStatus.OPEN_FAILED, dirty=True)

    (row,) = integrity_rows((hive,), ())

    assert row["value"] == "OPEN_FAILED"


def test_integrity_rows_put_lost_coverage_before_dirty_hives() -> None:
    """What the scan could not read leads the table, ahead of the softer caveat."""
    inventory = (
        HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED, dirty=True),
        HiveRecord(name="SYSTEM", status=HiveStatus.OPEN_FAILED),
    )
    failures = (CheckFailure(check_id="run_keys", error="boom"),)

    values = [row["value"] for row in integrity_rows(inventory, failures)]

    assert values == ["OPEN_FAILED", "boom", "Uncommitted transactions"]
