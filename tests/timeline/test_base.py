"""Tests for timestamp formatting, FILETIME conversion, and plausibility checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pyrsistencesniper.timeline.base import (
    Precision,
    TimeCandidate,
    format_ts,
    from_filetime,
    is_implausible,
)


def test_format_ts_renders_utc() -> None:
    """Timestamps render in one fixed, sortable form with no zone suffix to read."""
    when = datetime(2026, 2, 18, 15, 50, 59, tzinfo=UTC)
    assert format_ts(when) == "2026-02-18 15:50:59"


def test_format_ts_converts_to_utc() -> None:
    """A local-zone datetime is normalised, so reports compare across machines."""
    tz = timezone(timedelta(hours=2))
    when = datetime(2026, 2, 18, 17, 50, 59, tzinfo=tz)
    assert format_ts(when) == "2026-02-18 15:50:59"


def test_from_filetime_epoch() -> None:
    """1601-01-01 is the anchor every other conversion is offset from."""
    assert from_filetime(0) == datetime(1601, 1, 1, tzinfo=UTC)


def test_from_filetime_known_value() -> None:
    """A real FILETIME lands on the right day, catching a scale or epoch error."""
    # 2026-07-21 23:25:24.166053 UTC
    result = from_filetime(134291499241660537)
    assert result.year == 2026
    assert result.month == 7
    assert result.day == 21
    assert result.tzinfo == UTC


def test_is_implausible_rejects_pre_1990() -> None:
    """The FILETIME epoch itself is an unset field, not a change made in 1601."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert is_implausible(datetime(1601, 1, 1, tzinfo=UTC), now)


def test_is_implausible_rejects_far_future() -> None:
    """Past the skew allowance a date cannot describe a change that already happened."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    future = datetime(2026, 1, 5, tzinfo=UTC)
    assert is_implausible(future, now)


def test_is_implausible_accepts_recent() -> None:
    """An ordinary recent date survives the filter, which must not reject everything."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert not is_implausible(datetime(2025, 6, 1, tzinfo=UTC), now)


def test_time_candidate_is_frozen() -> None:
    """Collected evidence is immutable, so no resolver can rewrite another's finding."""
    candidate = TimeCandidate(
        when=datetime(2026, 1, 1, tzinfo=UTC),
        source="$MFT",
        precision=Precision.EXACT,
    )
    with pytest.raises(AttributeError):
        candidate.source = "other"  # type: ignore[misc]
