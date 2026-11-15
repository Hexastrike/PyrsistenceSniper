"""Tests for the $MFT parser: path reconstruction, fixups and timestamps."""

from __future__ import annotations

import io
import struct
from collections.abc import Sequence
from datetime import UTC, datetime

from pyrsistencesniper.timeline.mft import MftEntry, parse_mft

_RECORD_SIZE = 1024
_SECTOR_SIZE = 512
_USA_OFFSET = 0x30
_USA_COUNT = 3
_ATTRS_OFFSET = 0x38
_ATTR_HEADER_SIZE = 0x18
_ATTR_END = 0xFFFFFFFF
_ATTR_STANDARD_INFORMATION = 0x10
_ATTR_FILE_NAME = 0x30
_USN = b"\x99\x99"
_FLAG_IN_USE = 0x01
_FLAG_DIRECTORY = 0x02
_ROOT = 5

SI_CREATED_FT = 134291499241660537
SI_MODIFIED_FT = 134291499251660537
FN_CREATED_FT = 134291499261660537
FN_MODIFIED_FT = 134291499271660537
DOS_FN_CREATED_FT = 134291499281660537
DOS_FN_MODIFIED_FT = 134291499291660537

SI_CREATED_DT = datetime(2026, 7, 21, 23, 25, 24, 166053, tzinfo=UTC)
SI_MODIFIED_DT = datetime(2026, 7, 21, 23, 25, 25, 166053, tzinfo=UTC)
FN_CREATED_DT = datetime(2026, 7, 21, 23, 25, 26, 166053, tzinfo=UTC)
FN_MODIFIED_DT = datetime(2026, 7, 21, 23, 25, 27, 166053, tzinfo=UTC)


def _resident_attr(attr_type: int, value: bytes) -> bytes:
    """Build one resident attribute, padded to the 8-byte alignment NTFS uses."""
    length = _ATTR_HEADER_SIZE + len(value)
    length += (-length) % 8
    attr = bytearray(length)
    struct.pack_into("<II", attr, 0x00, attr_type, length)
    attr[0x08] = 0
    struct.pack_into("<I", attr, 0x10, len(value))
    struct.pack_into("<H", attr, 0x14, _ATTR_HEADER_SIZE)
    attr[_ATTR_HEADER_SIZE : _ATTR_HEADER_SIZE + len(value)] = value
    return bytes(attr)


def _si_value(created_filetime: int, modified_filetime: int) -> bytes:
    """Pack a $STANDARD_INFORMATION value; only created and modified differ."""
    return struct.pack(
        "<QQQQ",
        created_filetime,
        modified_filetime,
        modified_filetime,
        modified_filetime,
    )


def _fn_value(
    parent: int,
    created_filetime: int,
    modified_filetime: int,
    namespace: int,
    name: str,
) -> bytes:
    """Pack a $FILE_NAME value carrying the parent reference and namespace."""
    encoded = name.encode("utf-16-le")
    value = bytearray(0x42 + len(encoded))
    struct.pack_into("<Q", value, 0x00, parent)
    struct.pack_into("<Q", value, 0x08, created_filetime)
    struct.pack_into("<Q", value, 0x10, modified_filetime)
    struct.pack_into("<Q", value, 0x18, modified_filetime)
    struct.pack_into("<Q", value, 0x20, modified_filetime)
    value[0x40] = len(encoded) // 2
    value[0x41] = namespace
    value[0x42:] = encoded
    return bytes(value)


def build_file_record(
    record_number: int,
    parent: int,
    name: str,
    si_modified_filetime: int = SI_MODIFIED_FT,
    fn_modified_filetime: int = FN_MODIFIED_FT,
    namespace: int = 1,
    flags: int = _FLAG_IN_USE,
    *,
    si_created_filetime: int = SI_CREATED_FT,
    fn_created_filetime: int = FN_CREATED_FT,
    base_reference: int = 0,
    extra_file_names: Sequence[tuple[str, int, int, int]] = (),
) -> bytes:
    """Build a 1 KiB FILE record with valid fixups; defaults form a live file."""
    record = bytearray(_RECORD_SIZE)
    record[0:4] = b"FILE"
    struct.pack_into("<HH", record, 0x04, _USA_OFFSET, _USA_COUNT)
    struct.pack_into("<H", record, 0x10, 1)
    struct.pack_into("<H", record, 0x12, 1)
    struct.pack_into("<H", record, 0x14, _ATTRS_OFFSET)
    struct.pack_into("<H", record, 0x16, flags)
    struct.pack_into("<I", record, 0x1C, _RECORD_SIZE)
    struct.pack_into("<Q", record, 0x20, base_reference)
    struct.pack_into("<I", record, 0x2C, record_number)

    offset = _ATTRS_OFFSET
    attrs = [
        _resident_attr(
            _ATTR_STANDARD_INFORMATION,
            _si_value(si_created_filetime, si_modified_filetime),
        ),
        _resident_attr(
            _ATTR_FILE_NAME,
            _fn_value(
                parent, fn_created_filetime, fn_modified_filetime, namespace, name
            ),
        ),
    ]
    attrs.extend(
        _resident_attr(
            _ATTR_FILE_NAME,
            _fn_value(parent, created, modified, extra_namespace, extra_name),
        )
        for extra_name, extra_namespace, created, modified in extra_file_names
    )
    for attr in attrs:
        record[offset : offset + len(attr)] = attr
        offset += len(attr)
    struct.pack_into("<II", record, offset, _ATTR_END, 0)
    struct.pack_into("<I", record, 0x18, offset + 8)

    record[_USA_OFFSET : _USA_OFFSET + 2] = _USN
    for index in range(1, _USA_COUNT):
        sector_end = index * _SECTOR_SIZE
        saved = _USA_OFFSET + index * 2
        record[saved : saved + 2] = record[sector_end - 2 : sector_end]
        record[sector_end - 2 : sector_end] = _USN
    return bytes(record)


def _padding(count: int) -> bytes:
    """Return blank records so the next record lands on a chosen number."""
    return b"\x00" * (_RECORD_SIZE * count)


def _entries(data: bytes) -> list[MftEntry]:
    """Parse raw bytes as an $MFT and collect the entries into a list."""
    return list(parse_mft(io.BytesIO(data)))


def test_single_record_under_root_yields_entry_with_timestamps() -> None:
    """All four FILETIMEs decode, and a child of root needs no parent lookup."""
    entries = _entries(build_file_record(0, parent=_ROOT, name="evil.exe"))
    assert len(entries) == 1
    entry = entries[0]
    assert entry.record_number == 0
    assert entry.path == "evil.exe"
    assert entry.si_created == SI_CREATED_DT
    assert entry.si_modified == SI_MODIFIED_DT
    assert entry.fn_created == FN_CREATED_DT
    assert entry.fn_modified == FN_MODIFIED_DT


def test_parent_chain_reconstructs_full_path() -> None:
    """Full paths are what lookups key on, so parents must resolve to names."""
    data = _padding(6)
    data += build_file_record(
        6, parent=_ROOT, name="Windows", flags=_FLAG_IN_USE | _FLAG_DIRECTORY
    )
    data += build_file_record(7, parent=6, name="evil.exe")
    entries = _entries(data)
    assert {entry.record_number: entry.path for entry in entries} == {
        6: "Windows",
        7: "Windows\\evil.exe",
    }


def test_extension_record_is_skipped() -> None:
    """An extension record repeats its base file's name and would double-count."""
    data = build_file_record(
        0, parent=_ROOT, name="ghost.exe", base_reference=0x0001000000000006
    )
    data += build_file_record(1, parent=_ROOT, name="real.exe")
    entries = _entries(data)
    assert [entry.path for entry in entries] == ["real.exe"]
    assert entries[0].record_number == 1


def test_win32_name_upgrades_dos_short_name() -> None:
    """Evidence paths are long names; the 8.3 alias would never match a lookup."""
    record = build_file_record(
        0,
        parent=_ROOT,
        name="EVIL~1.EXE",
        namespace=2,
        fn_modified_filetime=DOS_FN_MODIFIED_FT,
        fn_created_filetime=DOS_FN_CREATED_FT,
        extra_file_names=(("evil.exe", 1, FN_CREATED_FT, FN_MODIFIED_FT),),
    )
    entries = _entries(record)
    assert len(entries) == 1
    assert entries[0].path == "evil.exe"
    assert entries[0].fn_created == FN_CREATED_DT
    assert entries[0].fn_modified == FN_MODIFIED_DT


def test_bad_fixup_record_is_skipped_and_next_record_parses() -> None:
    """A failed fixup means torn data; parsing must resync, not abort."""
    corrupt = bytearray(build_file_record(0, parent=_ROOT, name="broken.exe"))
    corrupt[_SECTOR_SIZE - 2] ^= 0xFF
    data = bytes(corrupt) + build_file_record(1, parent=_ROOT, name="ok.exe")
    entries = _entries(data)
    assert [entry.path for entry in entries] == ["ok.exe"]


def test_truncated_final_record_is_ignored() -> None:
    """A short tail from a partial acquisition costs only the last record."""
    data = build_file_record(0, parent=_ROOT, name="kept.exe")
    data += b"FILE" + b"\x00" * 100
    entries = _entries(data)
    assert [entry.path for entry in entries] == ["kept.exe"]


def test_out_of_range_filetime_record_is_skipped() -> None:
    """A timestomped FILETIME is dropped rather than crashing the whole parse."""
    wiped = build_file_record(
        0, parent=_ROOT, name="wiped.exe", si_modified_filetime=0xFFFFFFFFFFFFFFFF
    )
    data = wiped + build_file_record(1, parent=_ROOT, name="ok.exe")
    entries = _entries(data)
    assert [entry.path for entry in entries] == ["ok.exe"]
