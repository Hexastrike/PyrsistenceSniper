"""Offline registry hive access: pyregf-backed parsing and in-memory key trees."""

from __future__ import annotations

import errno
import io
import logging
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pyregf

from pyrsistencesniper.core.models import (
    CheckFailure,
    HiveProtocol,
    HiveRecord,
    HiveStatus,
    KeyProtocol,
)
from pyrsistencesniper.core.windows import _io_path, read_bounded

logger = logging.getLogger(__name__)

_MAX_REGISTRY_DEPTH = 64

# Repair holds the whole hive in memory twice, so a file past this size is left
# as an open failure rather than copied.
_MAX_REPAIR_BYTES = 1 << 30

# RunEx and RunOnceEx do not execute their own values: each command sits in an
# ordered section subkey below the key, so a flat read of these two reports
# nothing an attacker actually scheduled.
_SECTION_KEY_NAMES = frozenset({"runex", "runonceex"})

_REGF_SIGNATURE = b"regf"
_HIVE_BIN_SIGNATURE = b"hbin"
_BASE_BLOCK_SIZE = 4096
_HEADER_SIZE = 512
_CHECKSUM_OFFSET = 508
_SEQUENCE_OFFSET = 4
_SECONDARY_SEQUENCE_OFFSET = 8
_BINS_SIZE_OFFSET = 40
_CHECKSUM_ALL_ONES = 0xFFFFFFFF

__all__ = [
    "HiveHeader",
    "RegistryHelper",
    "RegistryNode",
    "commands_below",
    "hive_key",
    "read_hive_header",
    "registry_value_to_str",
    "stores_commands_in_sections",
]


@dataclass(frozen=True, slots=True)
class HiveHeader:
    """Integrity fields of a REGF base block."""

    primary_sequence: int = 0
    secondary_sequence: int = 0
    hive_bins_size: int = 0
    stored_checksum: int = 0
    computed_checksum: int = 0

    @property
    def dirty(self) -> bool:
        """Report whether the hive holds transactions its logs have not applied."""
        return self.primary_sequence != self.secondary_sequence

    @property
    def checksum_valid(self) -> bool:
        """Report whether the base block checksum matches the block's contents."""
        return self.stored_checksum == self.computed_checksum


def _base_block_checksum(block: bytes) -> int:
    """Return the XOR-32 checksum a REGF base block stores at offset 0x1FC."""
    checksum = 0
    for offset in range(0, _CHECKSUM_OFFSET, 4):
        checksum ^= struct.unpack_from("<I", block, offset)[0]
    if checksum == 0:
        return 1
    if checksum == _CHECKSUM_ALL_ONES:
        return 0xFFFFFFFE
    return checksum


def hive_key(path: Path) -> str:
    """Return the identity under which a hive's open attempt is recorded."""
    # RegistryHelper records attempts under this key and AnalysisContext looks
    # them up by it, so both must derive it identically. Recorded one way and
    # looked up another, a hive is reported as never read while its findings
    # appear in the same report.
    try:
        return str(path.resolve())
    except OSError:
        logger.debug("Cannot resolve hive path: %s", path, exc_info=True)
        return str(path)


def read_hive_header(path: Path) -> HiveHeader | None:
    """Parse a REGF base block, returning None when the file is not a hive."""
    try:
        with _io_path(path).open("rb") as hive_file:
            block = hive_file.read(_HEADER_SIZE)
    except OSError:
        logger.debug("Cannot read hive header: %s", path, exc_info=True)
        return None
    if len(block) < _HEADER_SIZE or not block.startswith(_REGF_SIGNATURE):
        return None
    primary, secondary = struct.unpack_from("<II", block, _SEQUENCE_OFFSET)
    return HiveHeader(
        primary_sequence=primary,
        secondary_sequence=secondary,
        hive_bins_size=struct.unpack_from("<I", block, _BINS_SIZE_OFFSET)[0],
        stored_checksum=struct.unpack_from("<I", block, _CHECKSUM_OFFSET)[0],
        computed_checksum=_base_block_checksum(block),
    )


def _last_intact_bin_end(data: bytes | bytearray) -> int:
    """Return the offset just past the last hive bin that is wholly present."""
    offset = _BASE_BLOCK_SIZE
    size = len(data)
    while offset + 12 <= size:
        if data[offset : offset + 4] != _HIVE_BIN_SIGNATURE:
            break
        bin_size = struct.unpack_from("<I", data, offset + 8)[0]
        if bin_size == 0 or bin_size % _BASE_BLOCK_SIZE or offset + bin_size > size:
            break
        offset += bin_size
    return offset


def _clamp_bin_list(data: bytearray) -> bool:
    """Rewrite a base block so its declared bin extent matches the bins present."""
    # libregf rejects the whole file rather than the damaged tail, so clamping
    # the extent to the last intact bin recovers everything before the damage.
    end = _last_intact_bin_end(data)
    if end <= _BASE_BLOCK_SIZE:
        return False
    struct.pack_into("<I", data, _BINS_SIZE_OFFSET, end - _BASE_BLOCK_SIZE)
    primary = struct.unpack_from("<I", data, _SEQUENCE_OFFSET)[0]
    struct.pack_into("<I", data, _SECONDARY_SEQUENCE_OFFSET, primary)
    struct.pack_into(
        "<I", data, _CHECKSUM_OFFSET, _base_block_checksum(bytes(data[:_HEADER_SIZE]))
    )
    return True


def registry_key_join(*parts: str) -> str:
    """Join registry key segments, skipping empty ones."""
    # A hive whose root is already the key of interest contributes an empty one.
    return "\\".join(part for part in parts if part)


def registry_value_to_str(raw_value: object) -> str | None:
    """Convert a registry value to a stripped string; return None if blank."""
    if raw_value is None:
        return None
    stripped_text = str(raw_value).strip()
    return stripped_text if stripped_text else None


def _pyregf_extract_data(pyregf_value: Any) -> object:  # noqa: ANN401
    """Convert a pyregf value to a native Python type (str, int, list, or bytes)."""
    value_type = pyregf_value.get_type()
    try:
        if value_type in (
            pyregf.value_types.STRING,
            pyregf.value_types.EXPANDABLE_STRING,
        ):
            return pyregf_value.get_data_as_string()
        if value_type in (
            pyregf.value_types.INTEGER_32BIT_LITTLE_ENDIAN,
            pyregf.value_types.INTEGER_64BIT_LITTLE_ENDIAN,
            pyregf.value_types.INTEGER_32BIT_BIG_ENDIAN,
        ):
            return pyregf_value.get_data_as_integer()
        if value_type == pyregf.value_types.MULTI_VALUE_STRING:
            return list(pyregf_value.get_data_as_multi_string())
    except Exception:
        logger.debug(
            "Registry value declares type %s but its data does not fit it; "
            "reading the raw bytes instead",
            value_type,
            exc_info=True,
        )
    data = pyregf_value.get_data()
    return data if data is not None else b""


class RegistryNode:
    """In-memory registry key with dict-based value and child lookups."""

    __slots__ = ("_children", "_values", "name")

    def __init__(
        self,
        name: str,
        values: dict[str, tuple[str, object]],
        children: dict[str, RegistryNode],
    ) -> None:
        self.name = name
        self._values = values
        self._children = children

    def get(self, value_name: str) -> object | None:
        """Return a value by name (case-insensitive)."""
        key = value_name.lower()
        if key == "(default)":
            key = ""
        entry = self._values.get(key)
        return entry[1] if entry is not None else None

    def child(self, name: str) -> RegistryNode | None:
        """Return a child subkey by name (case-insensitive), or None."""
        return self._children.get(name.lower())

    def children(self) -> Iterator[tuple[str, RegistryNode]]:
        """Yield (name, node) pairs for all child subkeys."""
        for node in self._children.values():
            yield (node.name, node)

    def values(self) -> Iterator[tuple[str, object]]:
        """Yield (name, data) pairs for all values in this key."""
        yield from self._values.values()


def stores_commands_in_sections(key_path: str) -> bool:
    """Report whether a key keeps its commands in ordered section subkeys."""
    return key_path.rsplit("\\", 1)[-1].lower() in _SECTION_KEY_NAMES


def _is_unnamed_default(value_name: str) -> bool:
    """Report whether a value is the unnamed default, which holds only a caption."""
    return not value_name or value_name == "(Default)"


def commands_below(
    node: RegistryNode | None, canonical_path: str
) -> Iterator[tuple[str, str]]:
    """Yield the canonical path and command of every named value below a key."""
    if node is None:
        return
    for child_name, child_node in node.children():
        child_path = f"{canonical_path}\\{child_name}"
        for value_name, raw_value in child_node.values():
            if _is_unnamed_default(value_name):
                continue
            command = registry_value_to_str(raw_value)
            if command is None:
                continue
            yield f"{child_path}\\{value_name}", command
        yield from commands_below(child_node, child_path)


# Integrity channel: keys read only in part, so a report can distinguish "found
# nothing here" from "could not look here". Reset per scan by
# reset_partial_reads().
_partial_reads: dict[str, str] = {}


def reset_partial_reads() -> None:
    """Forget the partial registry reads recorded by an earlier scan."""
    _partial_reads.clear()


def partial_reads() -> dict[str, str]:
    """Return the registry keys that could only be read in part, mapped to why."""
    return dict(_partial_reads)


def _record_partial_read(key_name: object, exc: Exception) -> None:
    """Note that a key lost values or subkeys, so the gap is reportable."""
    name = str(key_name) if key_name else "<unnamed key>"
    if name in _partial_reads:
        return
    _partial_reads[name] = _describe_failure(exc)
    logger.warning("Registry key %s could only be read in part: %s", name, exc)
    logger.debug("Registry read error details:", exc_info=True)


# The same integrity channel for artifacts a check found but could not parse.
# Reset by reset_artifact_failures().
_artifact_failures: dict[str, CheckFailure] = {}


def reset_artifact_failures() -> None:
    """Forget the artifact read failures recorded by an earlier scan."""
    _artifact_failures.clear()


def artifact_failures() -> tuple[CheckFailure, ...]:
    """Return the artifacts a check found but could not parse, as coverage it lost."""
    return tuple(
        _artifact_failures[identity] for identity in sorted(_artifact_failures)
    )


def _describe_failure(reason: BaseException | str) -> str:
    """Render a parse failure as the single line a report can carry."""
    if isinstance(reason, BaseException):
        return f"{type(reason).__name__}: {reason}"
    return str(reason)


def record_artifact_failure(
    check_id: str, artifact: Path | str, reason: BaseException | str
) -> None:
    """Note an artifact that exists but would not parse, so its silence is reported."""
    # An artifact the image never held is a real negative, not coverage the scan lost.
    if isinstance(reason, OSError) and reason.errno in (errno.ENOENT, errno.ENOTDIR):
        return
    identity = f"{check_id} artifact {artifact}"
    if identity in _artifact_failures:
        return
    error = _describe_failure(reason)
    _artifact_failures[identity] = CheckFailure(
        check_id=check_id, artifact=str(artifact), error=error
    )
    logger.warning("Check %s could not read artifact %s: %s", check_id, artifact, error)


def _count_or_zero(key: KeyProtocol, counter: str, name: str) -> int:
    """Return a pyregf child or value count, treating an unreadable count as empty."""
    try:
        return int(getattr(key, counter)())
    except Exception as exc:
        _record_partial_read(name, exc)
        return 0


def _value_at(
    key: KeyProtocol, index: int, name: str
) -> tuple[str, tuple[str, object]] | None:
    """Read one value cell, reporting None when libregf cannot follow it."""
    try:
        registry_value = key.get_value(index)
        value_name: str = registry_value.get_name() or ""
        return value_name.lower(), (value_name, _pyregf_extract_data(registry_value))
    except Exception as exc:
        _record_partial_read(name, exc)
        return None


def _child_at(
    key: KeyProtocol, index: int, name: str, depth: int
) -> tuple[str, RegistryNode] | None:
    """Read one subkey and its dict key, or None when libregf cannot follow it."""
    try:
        child = _materialize(key.get_sub_key(index), depth + 1)
        return child.name.lower(), child
    except Exception as exc:
        _record_partial_read(name, exc)
        return None


def _materialize(key: KeyProtocol, depth: int = 0) -> RegistryNode:
    """Convert a pyregf key and its children into a RegistryNode tree."""
    # A cell libregf cannot follow costs only its own value or subkey. Letting
    # it escape would unwind the whole check and report a damaged hive as clean.
    try:
        name: str = key.get_name() or ""
    except Exception as exc:
        _record_partial_read(None, exc)
        name = ""

    values: dict[str, tuple[str, object]] = {}
    for value_index in range(_count_or_zero(key, "get_number_of_values", name)):
        value_entry = _value_at(key, value_index, name)
        if value_entry is not None:
            values[value_entry[0]] = value_entry[1]

    children: dict[str, RegistryNode] = {}
    if depth < _MAX_REGISTRY_DEPTH:
        for child_index in range(_count_or_zero(key, "get_number_of_sub_keys", name)):
            child_entry = _child_at(key, child_index, name, depth)
            if child_entry is not None:
                children[child_entry[0]] = child_entry[1]
    elif _count_or_zero(key, "get_number_of_sub_keys", name):
        _record_partial_read(
            name, RecursionError(f"registry depth limit {_MAX_REGISTRY_DEPTH} reached")
        )

    return RegistryNode(name, values, children)


class RegistryHelper:
    """Offline registry hive parser built on pyregf with caching."""

    def __init__(self) -> None:
        self._hive_cache: dict[str, HiveProtocol | None] = {}
        self._subtree_cache: dict[tuple[int, str], RegistryNode | None] = {}
        self._attempts: dict[str, HiveRecord] = {}

    def open_attempts(self) -> dict[str, HiveRecord]:
        """Return what happened to every hive this helper was asked to open."""
        # A method, not an attribute: the test suite specs this class with
        # create_autospec, which supplies methods but not instance attributes.
        return dict(self._attempts)

    def open_hive(self, path: Path) -> HiveProtocol | None:
        """Open a registry hive file, caching by resolved path."""
        key = self._cache_key(path)
        if key in self._hive_cache:
            return self._hive_cache[key]

        header = read_hive_header(path)
        hive, status, error = self._load(path, header)
        self._hive_cache[key] = hive
        self._attempts[key] = HiveRecord(
            path=str(path),
            status=status,
            dirty=header is not None and header.dirty,
            error=error,
        )
        return hive

    @staticmethod
    def _cache_key(path: Path) -> str:
        """Return the cache key for a hive, which is also its inventory identity."""
        return hive_key(path)

    def _load(
        self, path: Path, header: HiveHeader | None
    ) -> tuple[HiveProtocol | None, HiveStatus, str]:
        """Open a hive, repairing an inconsistent bin list before giving up."""
        try:
            reg_file = pyregf.file()
            reg_file.open(str(_io_path(path)))
        except Exception as exc:
            error = _describe_failure(exc)
        else:
            return reg_file, HiveStatus.OPENED, ""

        logger.warning("Failed to open hive %s (%s)", path, error)
        logger.debug("Hive open error details:", exc_info=True)
        if header is None:
            return None, HiveStatus.OPEN_FAILED, error

        repaired = self._reopen_repaired(path)
        if repaired is None:
            return None, HiveStatus.OPEN_FAILED, error
        logger.warning("Recovered hive %s by clamping its hive bin list", path)
        return repaired, HiveStatus.REPAIRED, error

    @staticmethod
    def _reopen_repaired(path: Path) -> HiveProtocol | None:
        """Reopen a hive from a corrected copy held only in memory."""
        try:
            data = bytearray(read_bounded(path, _MAX_REPAIR_BYTES))
        except (OSError, ValueError):
            logger.debug("Cannot read hive for repair: %s", path, exc_info=True)
            return None
        if not _clamp_bin_list(data):
            return None
        try:
            reg_file = pyregf.file()
            reg_file.open_file_object(io.BytesIO(data))
        except Exception:
            logger.debug("Hive repair did not take for %s", path, exc_info=True)
            return None
        repaired: HiveProtocol = reg_file
        return repaired

    @staticmethod
    def _normalize_key_path(key_path: str) -> str:
        """Strip leading backslash for pyregf compatibility."""
        return key_path.lstrip("\\")

    def load_subtree(self, hive: HiveProtocol, key_path: str) -> RegistryNode | None:
        """Build and cache a RegistryNode tree for the given key path via DFS."""
        norm = self._normalize_key_path(key_path)
        cache_key = (id(hive), norm.lower())
        if cache_key in self._subtree_cache:
            return self._subtree_cache[cache_key]

        pyregf_key = self._resolve_key(hive, key_path)
        if pyregf_key is None:
            self._subtree_cache[cache_key] = None
            return None

        try:
            node = _materialize(pyregf_key)
        except Exception as exc:
            _record_partial_read(key_path, exc)
            self._subtree_cache[cache_key] = None
            return None
        self._subtree_cache[cache_key] = node
        return node

    @staticmethod
    def _resolve_key(hive: HiveProtocol, key_path: str) -> KeyProtocol | None:
        """Resolve a key path to a pyregf key, or None when it cannot be followed."""
        try:
            norm = RegistryHelper._normalize_key_path(key_path)
            return hive.get_key_by_path(norm)
        except Exception as exc:
            logger.debug("Could not resolve key %s", key_path, exc_info=True)
            _record_partial_read(key_path, exc)
            return None
