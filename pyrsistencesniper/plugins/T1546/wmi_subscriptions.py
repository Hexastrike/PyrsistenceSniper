"""Detection for WMI Event Subscription."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

from pyrsistencesniper.core.filesystem import safe_is_file
from pyrsistencesniper.core.ledger import record_artifact_failure
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FileWriteTime,
    Finding,
)
from pyrsistencesniper.core.windows import _io_path
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import BinaryIO

_CIM_PATHS: tuple[Path, ...] = (
    Path("Windows") / "System32" / "wbem" / "Repository" / "OBJECTS.DATA",
    Path("Windows") / "System32" / "wbem" / "Repository" / "FS" / "OBJECTS.DATA",
)

# Detection anchors on these instance records, never on property names: a name
# such as CommandLineTemplate belongs to the class schema Windows ships and is
# present on every machine, in every installed language.
_CONSUMER_CLASSES: tuple[str, ...] = (
    "ActiveScriptEventConsumer",
    "CommandLineEventConsumer",
    "LogFileEventConsumer",
    "NTEventLogEventConsumer",
    "SMTPEventConsumer",
)

_BINDING_RE = re.compile(
    rb"((?:ActiveScript|CommandLine|LogFile|NTEventLog|SMTP)EventConsumer)"
    rb'\.Name="([^"\x00]{1,256})"'
)

_FILTER_RE = re.compile(rb'__EventFilter\.Name="([^"\x00]{1,256})"')

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]+")

_HEADER_SEARCH = 1024
_BINDING_WINDOW = 512
_MIN_STRING = 4
_MAX_HEAP_STRINGS = 6
_MAX_PAYLOAD = 300

# The repository is read in overlapping windows, so a multi-gigabyte one costs
# time but not memory. The overlap only has to exceed the longest span a record
# scan reads past a match, which is the header search plus the longest heap.
_WINDOW_BYTES = 4 * 1024 * 1024
_OVERLAP_BYTES = 64 * 1024
_MAX_RECORDS = 10_000

# An instance heap opens with a little-endian length whose high bit is set, so
# the record itself states where its values end and a command line of any length
# is read whole. A record stating no length -- carved, or with its class name not
# heading the heap -- is read to the longest heap the overlap can carry across a
# read boundary, which is that overlap less the header search.
_HEAP_LENGTH_FLAG = 0x8000_0000
_HEAP_LENGTH_MASK = 0x7FFF_FFFF
_HEAP_LENGTH_BYTES = 4
_MAX_HEAP_BYTES = _OVERLAP_BYTES - _HEADER_SEARCH


def _class_name_hash(class_name: str) -> bytes:
    """Return the hashed class name that heads every instance record of a class."""
    digest = hashlib.sha256(class_name.upper().encode("utf-16-le")).hexdigest()
    return digest.upper().encode("utf-16-le")


_HEADER_RES: tuple[tuple[re.Pattern[bytes], str], ...] = tuple(
    (re.compile(re.escape(_class_name_hash(class_name))), class_name)
    for class_name in _CONSUMER_CLASSES
)


def _heap_end(data: bytes, heap_start: int, smallest_credible: int) -> int:
    """Return where the heap ends: the length the record declares, else the bound."""
    bound = min(heap_start + _MAX_HEAP_BYTES, len(data))
    field = data[max(heap_start - _HEAP_LENGTH_BYTES, 0) : heap_start]
    declared = int.from_bytes(field, "little")
    if not declared & _HEAP_LENGTH_FLAG:
        return bound
    length = declared & _HEAP_LENGTH_MASK
    if length < smallest_credible:
        return bound
    return min(heap_start + length, bound)


def _heap_values(data: bytes, start: int, class_name: str) -> list[str]:
    """Return the values stored in the instance heap that follows a class header."""
    marker = b"\x00" + class_name.encode("ascii") + b"\x00"
    index = data.find(marker, start, start + _HEADER_SEARCH)
    if index == -1:
        return []
    heap_end = _heap_end(data, index, len(marker))
    values: list[str] = []
    for run in _PRINTABLE_RE.finditer(data, index + len(marker), heap_end):
        if len(run.group()) < _MIN_STRING:
            continue
        text = run.group().decode("ascii")
        if text.startswith("__"):
            break
        values.append(text)
        if len(values) >= _MAX_HEAP_STRINGS:
            break
    return values


def _instance_heaps(window: bytes, cutoff: int) -> list[tuple[str, list[str]]]:
    """Return the class and stored values of every consumer instance record."""
    heaps: list[tuple[str, list[str]]] = []
    for header_re, class_name in _HEADER_RES:
        for match in header_re.finditer(window):
            if match.start() >= cutoff:
                break
            values = _heap_values(window, match.start(), class_name)
            if values:
                heaps.append((class_name, values))
    return heaps


def _bindings(
    window: bytes, cutoff: int, already_named: set[tuple[str, str]]
) -> list[tuple[str, str, str]]:
    """Return each not-yet-seen consumer binding with the filter it references."""
    found: list[tuple[str, str, str]] = []
    for match in _BINDING_RE.finditer(window):
        if match.start() >= cutoff:
            break
        class_name = match.group(1).decode("ascii")
        instance = match.group(2).decode("ascii", "replace")
        if (class_name, instance) in already_named:
            continue
        already_named.add((class_name, instance))
        found.append((class_name, instance, _nearest_filter(window, match.end())))
    return found


def _iter_windows(handle: BinaryIO) -> Iterator[tuple[bytes, int]]:
    """Yield each overlapping window with the offset past which matches are deferred."""
    window = handle.read(_WINDOW_BYTES)
    while window:
        block = handle.read(_WINDOW_BYTES)
        if not block:
            yield window, len(window)
            return
        yield window, max(len(window) - _OVERLAP_BYTES, 0)
        window = window[-_OVERLAP_BYTES:] + block


def _heap_index(
    heaps: list[tuple[str, list[str]]],
) -> dict[tuple[str, str], list[str]]:
    """Map each (class, value) pair to the values of the first heap holding it."""
    # Built once per repository. Scanning every heap per binding instead is
    # quadratic, and a crafted repository supplies both sides of that product.
    index: dict[tuple[str, str], list[str]] = {}
    for heap_class, values in heaps:
        for value in values:
            index.setdefault((heap_class, value), values)
    return index


def _payload_beside(
    index: dict[tuple[str, str], list[str]], class_name: str, instance: str
) -> str:
    """Return the longest value stored alongside a named instance."""
    values = index.get((class_name, instance))
    if values is None:
        return ""
    return max((value for value in values if value != instance), key=len, default="")


def _nearest_filter(data: bytes, offset: int) -> str:
    """Return the filter named closest after a consumer reference in a binding."""
    match = _FILTER_RE.search(data, offset, offset + _BINDING_WINDOW)
    return match.group(1).decode("ascii", "replace") if match else ""


def _describe_bound(
    class_name: str, instance: str, filter_name: str, payload: str
) -> str:
    """Render a consumer instance named by a binding, with its filter and payload."""
    description = f'{class_name} "{instance}"'
    if filter_name:
        description += f' bound to filter "{filter_name}"'
    if payload:
        description += f": {payload[:_MAX_PAYLOAD]}"
    return description


def _describe_unbound(class_name: str, values: list[str]) -> str:
    """Render an instance record that no surviving binding refers to."""
    joined = " | ".join(value[:_MAX_PAYLOAD] for value in values)
    return f"{class_name} instance: {joined}"


@register_plugin
class WmiEventSubscription(PersistencePlugin):
    """Detects WMI Event Subscription persistence entries."""

    definition = CheckDefinition(
        id="wmi_event_subscription",
        technique="WMI Event Subscription",
        mitre_id="T1546.003",
        description=(
            "WMI permanent event subscriptions (CommandLineEventConsumer, "
            "ActiveScriptEventConsumer) execute commands or scripts in "
            "response to system events. These persist in the CIM repository "
            "and survive reboots."
        ),
    )

    def run(self) -> list[Finding]:
        """Report consumer instances recorded in the CIM repository."""
        findings: list[Finding] = []

        for cim_relative in _CIM_PATHS:
            cim_path = self.filesystem.image_root / cim_relative
            if not safe_is_file(cim_path):
                continue
            heaps, bindings = self._read_records(cim_path)
            findings.extend(
                self._describe(heaps, bindings, str(PureWindowsPath(cim_relative)))
            )

        return findings

    def _read_records(
        self, cim_path: Path
    ) -> tuple[list[tuple[str, list[str]]], list[tuple[str, str, str]]]:
        """Stream the repository so its size costs the scan time but not memory."""
        heaps: list[tuple[str, list[str]]] = []
        bindings: list[tuple[str, str, str]] = []
        already_named: set[tuple[str, str]] = set()

        try:
            repository_bytes = _io_path(cim_path).stat().st_size
            with _io_path(cim_path).open("rb") as handle:
                for window, cutoff in _iter_windows(handle):
                    # The budget is spent as each window is appended rather than
                    # checked afterwards: one 4 MiB window holds far more records
                    # than the cap, so testing after the extend let a crafted
                    # repository overshoot it by an order of magnitude.
                    budget = max(_MAX_RECORDS - len(heaps) - len(bindings), 0)
                    window_heaps = _instance_heaps(window, cutoff)
                    kept_heaps = window_heaps[:budget]
                    heaps.extend(kept_heaps)
                    window_bindings = _bindings(window, cutoff, already_named)
                    kept_bindings = window_bindings[: budget - len(kept_heaps)]
                    bindings.extend(kept_bindings)
                    dropped = (len(window_heaps) - len(kept_heaps)) + (
                        len(window_bindings) - len(kept_bindings)
                    )
                    # Reported only when records were actually discarded, and
                    # with the count really kept: the previous message named the
                    # cap and claimed unread bytes even when neither was true.
                    if dropped:
                        record_artifact_failure(
                            self.definition.id,
                            cim_path,
                            f"stopped after {len(heaps) + len(bindings)} consumer "
                            f"records; {dropped} more in this window and the rest "
                            f"of the {repository_bytes} byte repository were not "
                            f"examined",
                        )
                        break
        except (OSError, MemoryError) as exc:
            record_artifact_failure(self.definition.id, cim_path, exc)

        return heaps, bindings

    def _describe(
        self,
        heaps: list[tuple[str, list[str]]],
        bindings: list[tuple[str, str, str]],
        cim_display: str,
    ) -> list[Finding]:
        """Emit one finding per consumer instance recorded in the repository."""
        findings: list[Finding] = []
        index = _heap_index(heaps)

        for class_name, instance, filter_name in bindings:
            findings.append(
                self._make_finding(
                    path=cim_display,
                    value=_describe_bound(
                        class_name,
                        instance,
                        filter_name,
                        _payload_beside(index, class_name, instance),
                    ),
                    access=AccessLevel.SYSTEM,
                    time_evidence=(FileWriteTime(path=cim_display, weak=True),),
                )
            )

        named = {instance for _class_name, instance, _filter_name in bindings}
        for class_name, values in heaps:
            if any(value in named for value in values):
                continue
            findings.append(
                self._make_finding(
                    path=cim_display,
                    value=_describe_unbound(class_name, values),
                    access=AccessLevel.SYSTEM,
                    time_evidence=(FileWriteTime(path=cim_display, weak=True),),
                )
            )

        return findings
