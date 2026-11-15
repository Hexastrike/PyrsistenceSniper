"""Timeline evidence primitives shared by resolvers and the executor."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
MIN_CREDIBLE = datetime(1990, 1, 1, tzinfo=UTC)
MAX_FUTURE_SKEW = timedelta(hours=48)


# Both tiers read timestamps carried inside the artifact's own bytes ($MFT
# records, event records), so they survive collection. EXACT maps to the
# mechanism itself; WEAK is the same kind of evidence diluted beyond it, such as
# a repository-wide WMI OBJECTS.DATA store. Filesystem mtimes are excluded from
# both: their provenance cannot be verified per file, so a collection copy time
# could masquerade as an original change time.
class Precision(enum.Enum):
    """How exactly a candidate maps to the finding's own change moment."""

    EXACT = "EXACT"
    WEAK = "WEAK"


@dataclass(frozen=True, slots=True)
class TimeCandidate:
    """One piece of timestamp evidence considered for a finding."""

    when: datetime
    source: str
    detail: str = ""
    precision: Precision = Precision.WEAK


def format_ts(when: datetime) -> str:
    """Render an aware datetime as a UTC timestamp string."""
    return when.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def from_filetime(filetime: int) -> datetime:
    """Convert a Windows FILETIME (100 ns ticks since 1601) to aware UTC."""
    return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)


def is_implausible(when: datetime, now: datetime) -> bool:
    """Report whether a timestamp cannot describe a real artifact change."""
    return when < MIN_CREDIBLE or when > now + MAX_FUTURE_SKEW
