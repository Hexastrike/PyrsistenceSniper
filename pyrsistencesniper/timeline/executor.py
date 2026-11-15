"""Executes each finding's declared time evidence and fills the change columns."""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.models import (
    ChangeEvidence,
    EventLogTime,
    FileWriteTime,
    Finding,
    TimeEvidence,
)
from pyrsistencesniper.timeline.base import (
    Precision,
    TimeCandidate,
    format_ts,
    is_implausible,
)
from pyrsistencesniper.timeline.evtx_index import EvtxIndex
from pyrsistencesniper.timeline.file_resolver import FileTimeResolver
from pyrsistencesniper.timeline.mft_index import MftIndex
from pyrsistencesniper.timeline.regpath import sysmon_target_candidates

logger = logging.getLogger(__name__)

_TIE_WINDOW = timedelta(seconds=2)
_CLASS_ORDER = (Precision.EXACT, Precision.WEAK)
_TIE_PREFERENCE = ("$MFT", "event log")

_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_SYSMON_REGISTRY_SET = (13,)


# A hive timestamps keys, not values, and the executed binary's own mtime dates
# the payload rather than the persistence entry, so a registry finding can only
# be dated from outside the hive. Sysmon event 13 records the write itself, which
# dates every declarative registry check here rather than plugin by plugin.
def _fallback_evidence(
    finding: Finding, sid_by_username: Mapping[str, str]
) -> tuple[TimeEvidence, ...]:
    """Return baseline evidence for a finding whose plugin declared none."""
    if not finding.path.upper().startswith(("HKLM\\", "HKU\\")):
        return (FileWriteTime(path=finding.resolve_target or finding.path),)
    return tuple(
        EventLogTime(
            channel=_SYSMON_CHANNEL,
            event_ids=_SYSMON_REGISTRY_SET,
            match_field="TargetObject",
            match_value=candidate,
        )
        for candidate in sysmon_target_candidates(finding.path, sid_by_username)
    )


def _tie_rank(candidate: TimeCandidate) -> int:
    """Rank a candidate's artifact against the tie-break preference order."""
    for rank, name in enumerate(_TIE_PREFERENCE):
        if name in candidate.source:
            return rank
    return len(_TIE_PREFERENCE)


def _select(candidates: list[TimeCandidate], now: datetime) -> TimeCandidate | None:
    """Pick the newest plausible candidate from the most exact class present."""
    eligible = [
        candidate for candidate in candidates if not is_implausible(candidate.when, now)
    ]
    for precision in _CLASS_ORDER:
        in_class = [
            candidate for candidate in eligible if candidate.precision is precision
        ]
        if not in_class:
            continue
        newest = max(candidate.when for candidate in in_class)
        tied = [
            candidate
            for candidate in in_class
            if newest - candidate.when <= _TIE_WINDOW
        ]
        tied.sort(
            key=lambda candidate: (
                _tie_rank(candidate),
                -candidate.when.timestamp(),
                candidate.source,
                candidate.detail,
            )
        )
        return tied[0]
    return None


def _winner_source(winner: TimeCandidate) -> str:
    """Name the winning candidate's artifact, marking a weak one as such."""
    if winner.precision is Precision.WEAK:
        return f"{winner.source} (weak)"
    return winner.source


def _candidate_line(candidate: TimeCandidate, now: datetime) -> str:
    """Render one candidate as an audit line for the report detail pane."""
    markers = " (weak)" if candidate.precision is Precision.WEAK else ""
    if is_implausible(candidate.when, now):
        markers += " (implausible)"
    line = f"{format_ts(candidate.when)} - {candidate.source}{markers}"
    return f"{line} - {candidate.detail}" if candidate.detail else line


class TimelineExecutor:
    """Resolves declared evidence per finding and picks the most exact answer."""

    def __init__(
        self,
        context: AnalysisContext,
        mft_path: Path | None = None,
    ) -> None:
        self._events = EvtxIndex(context.filesystem)
        self._profile_sids = context.profile_sids
        self._files = FileTimeResolver(
            MftIndex(context.filesystem, explicit_path=mft_path),
        )

    def timestamp(self, finding: Finding) -> Finding:
        """Return the finding with change columns filled from its evidence."""
        now = datetime.now(tz=UTC)
        descriptors = finding.time_evidence or _fallback_evidence(
            finding, self._profile_sids
        )
        if not descriptors:
            return dataclasses.replace(
                finding, change_evidence=ChangeEvidence.NOT_APPLICABLE
            )

        candidates: list[TimeCandidate] = []
        for descriptor in descriptors:
            candidates.extend(self._safe_resolve(descriptor, finding.check_id))
        if not candidates:
            return dataclasses.replace(
                finding, change_evidence=self._empty_reason(descriptors)
            )

        candidates.sort(
            key=lambda candidate: (
                -candidate.when.timestamp(),
                candidate.source,
                candidate.detail,
            ),
        )
        winner = _select(candidates, now)
        return dataclasses.replace(
            finding,
            last_change=format_ts(winner.when) if winner else "",
            change_source=_winner_source(winner) if winner else "",
            change_evidence=(
                ChangeEvidence.RESOLVED if winner else ChangeEvidence.REJECTED
            ),
            change_candidates=tuple(
                _candidate_line(candidate, now) for candidate in candidates
            ),
        )

    def _empty_reason(self, descriptors: tuple[TimeEvidence, ...]) -> ChangeEvidence:
        """Separate evidence that was never collected from evidence that missed."""
        if any(self._source_available(descriptor) for descriptor in descriptors):
            return ChangeEvidence.NO_MATCH
        return ChangeEvidence.NO_ARTIFACT

    def _source_available(self, descriptor: TimeEvidence) -> bool:
        """Report whether the artifact this descriptor reads was usable at all."""
        if isinstance(descriptor, FileWriteTime):
            return self._files.available
        return self._events.channel_available(descriptor.channel, descriptor.event_ids)

    def _safe_resolve(
        self,
        descriptor: TimeEvidence,
        check_id: str,
    ) -> list[TimeCandidate]:
        """Resolve one descriptor, dropping it if its artifact raises."""
        try:
            return self._resolve(descriptor)
        except Exception:
            logger.debug("Evidence resolution failed for %s", check_id, exc_info=True)
            return []

    def _resolve(self, descriptor: TimeEvidence) -> list[TimeCandidate]:
        """Turn one evidence descriptor into the candidates its artifact yields."""
        if isinstance(descriptor, FileWriteTime):
            return self._files.resolve_file(descriptor)
        return [
            TimeCandidate(
                when=hit.when,
                source="event log",
                detail=(
                    f"{descriptor.channel} event {hit.event_id} "
                    f"(record {hit.record_number}) matched "
                    f"{descriptor.match_field}={descriptor.match_value}"
                ),
                precision=Precision.EXACT,
            )
            for hit in self._events.matches(
                descriptor.channel,
                descriptor.event_ids,
                descriptor.match_field,
                descriptor.match_value,
            )
        ]
