"""Tests for the timeline executor: candidate ranking and change evidence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pyrsistencesniper.core.models import ChangeEvidence, Finding
from pyrsistencesniper.timeline import executor as executor_module
from pyrsistencesniper.timeline.base import Precision, TimeCandidate
from pyrsistencesniper.timeline.executor import (
    TimelineExecutor,
    _fallback_evidence,
)

_NOW = datetime(2026, 8, 10, tzinfo=UTC)


def _at(day: int) -> datetime:
    """A July 2026 timestamp, recent enough to pass the plausibility check."""
    return datetime(2026, 7, day, tzinfo=UTC)


class _StubExecutor(TimelineExecutor):
    """Executor whose evidence resolution is replaced with fixed candidates."""

    def __init__(
        self, candidates: list[TimeCandidate], *, source_available: bool = True
    ) -> None:
        """Skip the base __init__ so no event log or $MFT index is built."""
        self._canned = candidates
        self._available = source_available
        self._profile_sids: dict[str, str] = {}

    def _resolve(self, descriptor: object) -> list[TimeCandidate]:  # type: ignore[override]
        """Return the canned candidates, whatever descriptor is asked about."""
        return self._canned

    def _source_available(self, descriptor: object) -> bool:  # type: ignore[override]
        """Report the fixed availability that separates NO_MATCH from NO_ARTIFACT."""
        return self._available


def _freeze(monkeypatch) -> None:
    """Freeze the clock, so the plausibility window is the same on every run."""
    monkeypatch.setattr(
        executor_module,
        "datetime",
        type("D", (), {"now": staticmethod(lambda tz: _NOW)}),
    )


def _stamp(
    candidates: list[TimeCandidate], monkeypatch, *, source_available: bool = True
) -> Finding:
    """Run the stub over a file finding with the clock frozen at _NOW."""
    _freeze(monkeypatch)
    executor = _StubExecutor(candidates, source_available=source_available)
    # a file path, so exactly one fallback descriptor is produced
    return executor.timestamp(Finding(path="Windows\\System32\\Tasks\\Evil"))


def test_exact_beats_newer_weak(monkeypatch) -> None:
    """Precision outranks recency: a diluted source never beats a proven one."""
    result = _stamp(
        [
            TimeCandidate(_at(20), "event log", precision=Precision.EXACT),
            TimeCandidate(_at(25), "$MFT", precision=Precision.WEAK),
        ],
        monkeypatch,
    )
    assert result.change_source == "event log"
    assert result.last_change == "2026-07-20 00:00:00"


def test_newest_wins_within_class(monkeypatch) -> None:
    """The most recent write is the change being reported, not the first one seen."""
    result = _stamp(
        [
            TimeCandidate(_at(20), "event log", precision=Precision.EXACT),
            TimeCandidate(_at(22), "event log", precision=Precision.EXACT),
        ],
        monkeypatch,
    )
    assert result.last_change == "2026-07-22 00:00:00"


def test_weak_winner_is_suffixed(monkeypatch) -> None:
    """A weak answer is labelled, so a reader never reads it as a proven time."""
    result = _stamp(
        [TimeCandidate(_at(20), "$MFT", precision=Precision.WEAK)],
        monkeypatch,
    )
    assert result.change_source == "$MFT (weak)"


def test_tie_prefers_mft_over_event_log(monkeypatch) -> None:
    """Records seconds apart are one write, so the choice stays deterministic."""
    base = _at(20)
    result = _stamp(
        [
            TimeCandidate(base, "event log", precision=Precision.EXACT),
            TimeCandidate(
                base + timedelta(seconds=1), "$MFT", precision=Precision.EXACT
            ),
        ],
        monkeypatch,
    )
    assert result.change_source == "$MFT"


def test_implausible_never_wins_but_stays_in_candidates(monkeypatch) -> None:
    """A refused timestamp stays visible, since a zeroed one is itself a signal."""
    result = _stamp(
        [
            TimeCandidate(
                datetime(1601, 1, 1, tzinfo=UTC),
                "$MFT",
                precision=Precision.EXACT,
            ),
            TimeCandidate(_at(20), "event log", precision=Precision.EXACT),
        ],
        monkeypatch,
    )
    assert result.change_source == "event log"
    assert any("implausible" in c for c in result.change_candidates)


def test_no_candidates_leaves_the_columns_empty(monkeypatch) -> None:
    """An undated finding shows blank rather than a guessed or defaulted time."""
    result = _stamp([], monkeypatch)
    assert result.last_change == ""
    assert result.change_source == ""
    assert result.change_candidates == ()


def test_present_artifact_with_no_hit_records_no_match(monkeypatch) -> None:
    """The artifact was read and simply had nothing to say about this finding."""
    result = _stamp([], monkeypatch, source_available=True)
    assert result.change_evidence is ChangeEvidence.NO_MATCH


def test_absent_artifact_records_no_artifact(monkeypatch) -> None:
    """Nothing was collected that could date this, which is a collection gap."""
    result = _stamp([], monkeypatch, source_available=False)
    assert result.change_evidence is ChangeEvidence.NO_ARTIFACT


def test_registry_finding_with_no_matchable_spelling_is_not_applicable(
    monkeypatch,
) -> None:
    """An HKU path whose owner has no SID is undatable, not merely unmatched."""
    # Sysmon logs the account SID, so with no SID there is no string to look for.
    _freeze(monkeypatch)
    result = _StubExecutor([]).timestamp(Finding(path="HKU\\jdoe\\Software\\Run"))
    assert result.change_evidence is ChangeEvidence.NOT_APPLICABLE


def test_resolved_finding_records_resolved(monkeypatch) -> None:
    """A dated finding says so, so the column is never ambiguous."""
    result = _stamp(
        [TimeCandidate(_at(20), "event log", precision=Precision.EXACT)], monkeypatch
    )
    assert result.change_evidence is ChangeEvidence.RESOLVED


def test_only_implausible_candidates_record_rejected(monkeypatch) -> None:
    """Candidates were found and every one of them was refused."""
    ancient = datetime(1601, 1, 1, tzinfo=UTC)
    result = _stamp(
        [TimeCandidate(ancient, "$MFT", precision=Precision.EXACT)], monkeypatch
    )
    assert result.change_evidence is ChangeEvidence.REJECTED
    assert result.last_change == ""


def test_untouched_finding_records_not_run() -> None:
    """A finding the timeline stage never saw carries the neutral state."""
    assert Finding().change_evidence is ChangeEvidence.NOT_RUN


def test_fallback_machine_registry_finding_asks_sysmon() -> None:
    """A hive dates keys, not values, so only Sysmon event 13 can date the write."""
    evidence = _fallback_evidence(Finding(path="HKLM\\SOFTWARE\\Run\\Evil"), {})
    assert len(evidence) == 1
    assert evidence[0].channel == "Microsoft-Windows-Sysmon/Operational"
    assert evidence[0].event_ids == (13,)
    assert evidence[0].match_field == "TargetObject"
    assert evidence[0].match_value == "HKLM\\SOFTWARE\\Run\\Evil"


def test_fallback_user_registry_finding_is_keyed_on_the_sid() -> None:
    """Sysmon writes the account SID, never the profile directory name."""
    evidence = _fallback_evidence(
        Finding(path="HKU\\jdoe\\Software\\Run\\Evil"), {"jdoe": "S-1-5-21-7-8-9-1001"}
    )
    assert [item.match_value for item in evidence] == [
        "HKU\\S-1-5-21-7-8-9-1001\\Software\\Run\\Evil"
    ]


def test_fallback_user_registry_finding_without_a_sid_gets_nothing() -> None:
    """An unmatchable descriptor would report a gap as a miss, so none is offered."""
    assert _fallback_evidence(Finding(path="HKU\\jdoe\\Software\\Run"), {}) == ()


def test_fallback_control_set_finding_offers_both_spellings() -> None:
    """Sysmon saw CurrentControlSet where the offline hive is numbered."""
    evidence = _fallback_evidence(
        Finding(path="HKLM\\SYSTEM\\ControlSet001\\Services\\Evil\\ImagePath"), {}
    )
    assert [item.match_value for item in evidence] == [
        "HKLM\\SYSTEM\\ControlSet001\\Services\\Evil\\ImagePath",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Evil\\ImagePath",
    ]


def test_fallback_file_finding_gets_file_evidence() -> None:
    """A path outside the hives is dated from the filesystem, not the event log."""
    evidence = _fallback_evidence(Finding(path="Windows\\System32\\Tasks\\Evil"), {})
    assert len(evidence) == 1


def test_fallback_prefers_resolve_target() -> None:
    """The resolved target is the file worth dating, not the pointer to it."""
    finding = Finding(path="a.lnk", resolve_target="Users\\x\\evil.exe")
    evidence = _fallback_evidence(finding, {})
    assert evidence[0].path == "Users\\x\\evil.exe"  # type: ignore[union-attr]


def test_raising_resolver_is_isolated(monkeypatch) -> None:
    """A resolver that throws costs one timestamp, not the whole scan."""
    _freeze(monkeypatch)

    class _Boom(_StubExecutor):
        """Stub whose resolution always raises, as a corrupt artifact would."""

        def __init__(self) -> None:
            """Mark the source unavailable, so any result must come from _resolve."""
            super().__init__([], source_available=False)

        def _resolve(self, descriptor: object) -> list[TimeCandidate]:  # type: ignore[override]
            """Fail the way a truncated or unreadable artifact would."""
            raise RuntimeError("boom")

    result = _Boom().timestamp(Finding(path="Windows\\System32\\Tasks\\Evil"))
    assert result.last_change == ""
