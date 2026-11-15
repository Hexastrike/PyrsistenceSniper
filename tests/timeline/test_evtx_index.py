"""Tests for the EVTX index: channel lookup, field matching, and cleared logs."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import pytest
from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.timeline import evtx_index as evtx_module
from pyrsistencesniper.timeline.evtx_index import EvtxIndex

# python-evtx yields namespaced XML; without it the index finds no EventID at all.
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


class _FakeRecord:
    """Stand-in for a python-evtx record: one canned event and its record number."""

    def __init__(self, event_id: int, field: str, value: str, num: int) -> None:
        self._xml = (
            f'<Event xmlns="{_NS}"><System>'
            f"<EventID>{event_id}</EventID></System>"
            f'<EventData><Data Name="{field}">{value}</Data></EventData></Event>'
        )
        self._num = num

    def xml(self) -> str:
        """Well-formed record body, so parsing never counts this record unreadable."""
        return self._xml

    def timestamp(self) -> datetime:
        """Naive datetime, as python-evtx returns; the index is what attaches UTC."""
        return datetime(2026, 7, 21, 12, 0, 0)

    def record_num(self) -> int:
        """Record number, carried onto the hit so evidence cites the exact record."""
        return self._num


class _FakeHeader:
    """Stand-in for the EVTX file header, the two counts the cleared check reads."""

    def __init__(self, chunks: int, next_record: int) -> None:
        self._chunks = chunks
        self._next = next_record

    def chunk_count(self) -> int:
        """Chunk count, one half of the cleared-log signature the parser checks."""
        return self._chunks

    def next_record_number(self) -> int:
        """A number far past what one chunk could hold is how a cleared log shows."""
        return self._next


class _FakeEvtx:
    """Minimal Evtx reader serving canned records by path and logging every open."""

    records_by_path: ClassVar[dict[str, list[_FakeRecord]]] = {}
    header_by_path: ClassVar[dict[str, _FakeHeader]] = {}
    opened: ClassVar[list[str]] = []

    def __init__(self, path: str) -> None:
        self._path = path
        _FakeEvtx.opened.append(path)

    def __enter__(self) -> _FakeEvtx:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get_file_header(self) -> _FakeHeader:
        """Header for the path; the default stands for a log that was never cleared."""
        return _FakeEvtx.header_by_path.get(self._path, _FakeHeader(5, 100))

    def records(self) -> list[_FakeRecord]:
        """Canned records; an unregistered path is an empty log, not a missing one."""
        return _FakeEvtx.records_by_path.get(self._path, [])


@pytest.fixture(autouse=True)
def _reset_fake(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear the fake's class state and swap it in for the real Evtx reader."""
    _FakeEvtx.records_by_path = {}
    _FakeEvtx.header_by_path = {}
    _FakeEvtx.opened = []
    monkeypatch.setattr(evtx_module.EvtxReader, "Evtx", _FakeEvtx)


def _logs_dir(root: Path) -> Path:
    """Create the winevt Logs directory the index probes, and return it."""
    logs = root / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True, exist_ok=True)
    return logs


def _seed_log(root: Path, name: str, *records: _FakeRecord) -> str:
    """Place a stub log under winevt, register its records, and return its path."""
    log = _logs_dir(root) / name
    log.write_bytes(b"x")
    _FakeEvtx.records_by_path[str(log)] = list(records)
    return str(log)


def test_matches_by_field(tmp_path: Path) -> None:
    """Field comparison is case-folded, and the naive record time comes back as UTC."""
    _seed_log(tmp_path, "System.evtx", _FakeRecord(7045, "ServiceName", "EvilSvc", 3))
    index = EvtxIndex(FilesystemHelper(tmp_path))
    hits = index.matches("System", (7045,), "ServiceName", "evilsvc")
    assert len(hits) == 1
    assert hits[0].event_id == 7045
    assert hits[0].when.tzinfo == UTC


def test_wrong_event_id_filtered(tmp_path: Path) -> None:
    """An exact field match on the wrong event id is still no hit."""
    _seed_log(tmp_path, "System.evtx", _FakeRecord(7040, "ServiceName", "EvilSvc", 3))
    index = EvtxIndex(FilesystemHelper(tmp_path))
    assert index.matches("System", (7045,), "ServiceName", "EvilSvc") == []


def test_double_encoded_filename_probe(tmp_path: Path) -> None:
    """Images written with %254 for the channel separator still resolve to a log."""
    _seed_log(
        tmp_path,
        "Microsoft-Windows-TaskScheduler%254Operational.evtx",
        _FakeRecord(106, "TaskName", "\\Evil", 1),
    )
    index = EvtxIndex(FilesystemHelper(tmp_path))
    hits = index.matches(
        "Microsoft-Windows-TaskScheduler/Operational", (106,), "TaskName", "Evil"
    )
    assert len(hits) == 1


def test_cleared_log_yields_nothing(tmp_path: Path) -> None:
    """A cleared log holding a matching record is refused, not reported as evidence."""
    path = _seed_log(
        tmp_path, "Security.evtx", _FakeRecord(4698, "TaskName", "\\Evil", 1)
    )
    _FakeEvtx.header_by_path[path] = _FakeHeader(1, 11_000_000)
    index = EvtxIndex(FilesystemHelper(tmp_path))
    assert index.matches("Security", (4698,), "TaskName", "\\Evil") == []


def test_absent_log_yields_nothing(tmp_path: Path) -> None:
    """A channel the image never collected is a clean absence, not a scan failure."""
    _logs_dir(tmp_path)
    index = EvtxIndex(FilesystemHelper(tmp_path))
    assert index.matches("System", (7045,), "ServiceName", "x") == []


def test_channel_parsed_once(tmp_path: Path) -> None:
    """Every finding on a channel would otherwise re-read the whole log."""
    log = _seed_log(
        tmp_path, "System.evtx", _FakeRecord(7045, "ServiceName", "EvilSvc", 3)
    )
    index = EvtxIndex(FilesystemHelper(tmp_path))
    index.matches("System", (7045,), "ServiceName", "EvilSvc")
    index.matches("System", (7045,), "ServiceName", "Other")
    assert _FakeEvtx.opened.count(log) == 1


def test_records_outside_the_wanted_ids_are_not_retained(tmp_path: Path) -> None:
    """The id filter runs while parsing, so unwanted records never reach the cache."""
    # A tuned Sysmon log is tens of megabytes: retaining every record with its full
    # field dict costs memory for records no query can ever return.
    _seed_log(
        tmp_path,
        "Microsoft-Windows-Sysmon%4Operational.evtx",
        _FakeRecord(1, "Image", "evil.exe", 1),
        _FakeRecord(13, "TargetObject", "HKLM\\SOFTWARE\\Run\\Evil", 2),
        _FakeRecord(5, "Image", "evil.exe", 3),
    )
    index = EvtxIndex(FilesystemHelper(tmp_path))
    channel = "Microsoft-Windows-Sysmon/Operational"
    assert (
        len(index.matches(channel, (13,), "TargetObject", "HKLM\\SOFTWARE\\Run\\Evil"))
        == 1
    )
    retained = index._records[(channel, (13,))]
    assert [record[1] for record in retained] == [13]


def test_the_cache_is_keyed_on_the_id_set(tmp_path: Path) -> None:
    """A second query for different ids re-reads rather than reusing a filtered list."""
    _seed_log(
        tmp_path,
        "System.evtx",
        _FakeRecord(7045, "ServiceName", "EvilSvc", 1),
        _FakeRecord(7040, "ServiceName", "EvilSvc", 2),
    )
    index = EvtxIndex(FilesystemHelper(tmp_path))
    assert len(index.matches("System", (7045,), "ServiceName", "EvilSvc")) == 1
    assert len(index.matches("System", (7040,), "ServiceName", "EvilSvc")) == 1
    assert len(_FakeEvtx.opened) == 2


def test_repeating_a_query_reads_the_log_once(tmp_path: Path) -> None:
    """The cache holds the parsed records, so a second match value costs no I/O."""
    _seed_log(tmp_path, "System.evtx", _FakeRecord(7045, "ServiceName", "EvilSvc", 1))
    index = EvtxIndex(FilesystemHelper(tmp_path))
    index.matches("System", (7045,), "ServiceName", "EvilSvc")
    index.matches("System", (7045,), "ServiceName", "OtherSvc")
    assert len(_FakeEvtx.opened) == 1


def test_a_channel_holding_none_of_the_wanted_ids_is_still_available(
    tmp_path: Path,
) -> None:
    """Filtering must not turn a collected log into a missing one."""
    # channel_available separates "go and collect this artifact" from "the artifact
    # is here and says nothing about this finding".
    _seed_log(tmp_path, "System.evtx", _FakeRecord(7040, "ServiceName", "EvilSvc", 1))
    index = EvtxIndex(FilesystemHelper(tmp_path))
    assert index.matches("System", (7045,), "ServiceName", "EvilSvc") == []
    assert index.channel_available("System", (7045,)) is True


def test_an_absent_channel_is_not_available(tmp_path: Path) -> None:
    """A log the image never had is reported missing, so it can be asked for."""
    index = EvtxIndex(FilesystemHelper(tmp_path))
    assert index.channel_available("System", (7045,)) is False


def test_a_descriptor_naming_no_event_id_matches_nothing(tmp_path: Path) -> None:
    """The parse-time filter reads an empty id set as "keep all", matching must not."""
    _seed_log(tmp_path, "System.evtx", _FakeRecord(7045, "ServiceName", "EvilSvc", 1))
    index = EvtxIndex(FilesystemHelper(tmp_path))
    assert index.matches("System", (), "ServiceName", "EvilSvc") == []
