"""Lazy per-channel event log index for time evidence correlation."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import Evtx.Evtx as EvtxReader
from defusedxml import ElementTree

from pyrsistencesniper.core.filesystem import FilesystemHelper, safe_is_file
from pyrsistencesniper.core.windows import io_path

logger = logging.getLogger(__name__)

_LOGS_DIR = "Windows\\System32\\winevt\\Logs"
_MAX_LOG_BYTES = 256 * 1024 * 1024
_CLEARED_NEXT_RECORD_FLOOR = 10_000
_XML_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass(frozen=True, slots=True)
class EventHit:
    """One event record matched to a finding's evidence declaration."""

    when: datetime
    event_id: int
    record_number: int


class EvtxIndex:
    """Indexes requested event log channels once and answers match queries."""

    def __init__(self, filesystem: FilesystemHelper) -> None:
        self._fs = filesystem
        self._records: dict[
            tuple[str, tuple[int, ...]],
            list[tuple[datetime, int, int, dict[str, str]]],
        ] = {}
        self._readable: dict[str, bool] = {}

    # Deliberately separate from whether any record survived the event id filter:
    # a channel holding none of the wanted ids was still collected, and calling it
    # missing sends an analyst looking for a log they already have.
    def channel_available(self, channel: str, event_ids: tuple[int, ...] = ()) -> bool:
        """Report whether the channel was present and parsed."""
        self._load(channel, event_ids)
        return self._readable.get(channel, False)

    def matches(
        self,
        channel: str,
        event_ids: tuple[int, ...],
        match_field: str,
        match_value: str,
    ) -> list[EventHit]:
        """Return records on the channel whose data field equals the value."""
        if not event_ids:
            # The parse-time filter reads an empty set as "keep all", so a
            # descriptor naming no event id has to be rejected here instead.
            return []
        wanted = match_value.casefold().lstrip("\\")
        hits: list[EventHit] = []
        for when, event_id, record_number, data in self._load(channel, event_ids):
            actual = data.get(match_field, "").casefold().lstrip("\\")
            if actual and actual == wanted:
                hits.append(EventHit(when, event_id, record_number))
        return hits

    def _load(
        self, channel: str, event_ids: tuple[int, ...]
    ) -> list[tuple[datetime, int, int, dict[str, str]]]:
        """Return the channel's records for these ids, parsing on first request."""
        # Keyed on the id set as well as the channel because the filter runs while
        # parsing: a tuned Sysmon log reaches tens of megabytes, and holding every
        # record with its full field dict costs memory no scan needs.
        key = (channel, tuple(sorted(set(event_ids))))
        if key not in self._records:
            path = self._locate(channel)
            parsed = self._parse(path, key[1]) if path else None
            self._readable[channel] = parsed is not None
            self._records[key] = parsed if parsed is not None else []
        return self._records[key]

    def _locate(self, channel: str) -> Path | None:
        """Find the channel's .evtx file, trying both escapings of its name."""
        base = channel.replace("/", "%4")
        for name in (f"{base}.evtx", f"{base.replace('%', '%25')}.evtx"):
            candidate = self._fs.resolve(f"{_LOGS_DIR}\\{name}")
            if safe_is_file(candidate):
                return candidate
        logger.debug("Event log not present: %s", channel)
        return None

    def _parse(
        self, path: Path, event_ids: tuple[int, ...]
    ) -> list[tuple[datetime, int, int, dict[str, str]]] | None:
        """Read the log, keeping only the wanted ids; an empty set keeps all."""
        # None and [] must stay distinct to the caller: a log that could not be
        # read, versus a log that was read and holds none of the wanted ids.
        try:
            if io_path(path).stat().st_size > _MAX_LOG_BYTES:
                logger.warning("Skipping oversized event log %s", path.name)
                return None
        except OSError:
            logger.debug("Cannot stat event log: %s", path, exc_info=True)
            return None
        records: list[tuple[datetime, int, int, dict[str, str]]] = []
        unreadable = 0
        try:
            with EvtxReader.Evtx(str(io_path(path))) as log:
                header = log.get_file_header()
                if (
                    header.chunk_count() <= 1
                    and header.next_record_number() > _CLEARED_NEXT_RECORD_FLOOR
                ):
                    logger.warning("Event log %s appears cleared", path.name)
                    return None
                for record in log.records():
                    parsed = self._parse_record(record)
                    if parsed is None:
                        unreadable += 1
                    elif not event_ids or parsed[1] in event_ids:
                        records.append(parsed)
        except Exception:
            logger.warning("Failed to parse event log %s", path.name)
            logger.debug("Event log parse error details:", exc_info=True)
            return None
        if unreadable:
            logger.warning(
                "Skipped %d unreadable record(s) in %s; timestamps drawn from "
                "this channel are incomplete",
                unreadable,
                path.name,
            )
        return records

    @staticmethod
    def _parse_record(
        record: EvtxReader.Record,
    ) -> tuple[datetime, int, int, dict[str, str]] | None:
        """Extract time, event id, record number and data fields from a record."""
        try:
            root = ElementTree.fromstring(record.xml())
        except Exception:
            return None
        event_id_node = root.find(f"{_XML_NS}System/{_XML_NS}EventID")
        if event_id_node is None or not (event_id_node.text or "").strip().isdigit():
            return None
        data: dict[str, str] = {}
        for node in root.iter(f"{_XML_NS}Data"):
            name = node.get("Name")
            if name:
                data[name] = node.text or ""
        when = record.timestamp().replace(tzinfo=UTC)
        return when, int((event_id_node.text or "").strip()), record.record_num(), data
