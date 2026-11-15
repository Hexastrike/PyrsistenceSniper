"""Tests for FileTimeResolver: $MFT lookups, precision, timestomp hints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import FileWriteTime
from pyrsistencesniper.timeline.base import Precision
from pyrsistencesniper.timeline.file_resolver import FileTimeResolver
from pyrsistencesniper.timeline.mft import MftEntry


def _entry(**kwargs: object) -> MftEntry:
    """Build an MFT entry whose fields default to a clean, non-timestomped file."""
    base = {
        "record_number": 42,
        "path": "windows\\system32\\tasks\\evil",
        "si_created": datetime(2026, 7, 1, tzinfo=UTC),
        "si_modified": datetime(2026, 7, 20, tzinfo=UTC),
        "fn_created": datetime(2026, 7, 1, tzinfo=UTC),
        "fn_modified": datetime(2026, 7, 1, tzinfo=UTC),
    }
    base.update(kwargs)
    return MftEntry(**base)  # type: ignore[arg-type]


def _resolver(entry: MftEntry | None) -> FileTimeResolver:
    """Build a resolver whose index returns the given entry for every path."""
    index = MagicMock()
    index.lookup.return_value = entry
    return FileTimeResolver(index)


def test_mft_hit_yields_exact_candidate() -> None:
    """SI modified time, not created, is what dates a persistence write."""
    out = _resolver(_entry()).resolve_file(FileWriteTime(path="a\\b"))
    assert len(out) == 1
    assert out[0].source == "$MFT"
    assert out[0].precision is Precision.EXACT
    assert out[0].when == datetime(2026, 7, 20, tzinfo=UTC)


def test_weak_evidence_grades_weak() -> None:
    """Confidence follows the caller's weak flag, not the quality of the $MFT hit."""
    out = _resolver(_entry()).resolve_file(FileWriteTime(path="a\\b", weak=True))
    assert out[0].precision is Precision.WEAK


def test_no_mft_hit_yields_nothing() -> None:
    """A file absent from the $MFT contributes no timeline entry, and no error."""
    assert _resolver(None).resolve_file(FileWriteTime(path="a\\b")) == []


def test_mft_hit_without_si_modified_yields_nothing() -> None:
    """A record with no modified time yields nothing rather than a timeless one."""
    out = _resolver(_entry(si_modified=None)).resolve_file(FileWriteTime(path="a"))
    assert out == []


def test_timestomp_hint_when_si_predates_fn() -> None:
    """$SI is user-settable and $FN is not, so si before fn reads as backdating."""
    entry = _entry(
        si_modified=datetime(2020, 1, 1, tzinfo=UTC),
        fn_modified=datetime(2026, 7, 1, tzinfo=UTC),
    )
    out = _resolver(entry).resolve_file(FileWriteTime(path="a"))
    assert "timestomping hint" in out[0].detail


def test_no_timestomp_hint_within_slack() -> None:
    """Ordinary writes leave a small $SI/$FN gap, so slack keeps the hint quiet."""
    when = datetime(2026, 7, 1, tzinfo=UTC)
    entry = _entry(si_modified=when, fn_modified=when + timedelta(seconds=5))
    out = _resolver(entry).resolve_file(FileWriteTime(path="a"))
    assert "timestomping hint" not in out[0].detail
