"""Parser for the target a Windows shell link names, per the MS-SHLLINK format."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from pyrsistencesniper.core.registry import record_artifact_failure
from pyrsistencesniper.core.windows import (
    canonicalize_windows_path,
    expand_env_vars,
    read_bounded,
)

__all__ = [
    "ShellLink",
    "describe_shortcut_entry",
    "parse_shell_link",
    "read_shell_link",
    "resolve_shortcut_target",
]

_HEADER_SIZE = 0x4C
_LINK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

# A shell link is a few kilobytes; anything larger is not one, and reading it
# whole would hand an attacker-supplied file a memory budget it never earned.
_MAX_SHELL_LINK_BYTES = 1 << 20

_HAS_LINK_TARGET_ID_LIST = 0x0001
_HAS_LINK_INFO = 0x0002
_HAS_NAME = 0x0004
_HAS_RELATIVE_PATH = 0x0008
_HAS_WORKING_DIR = 0x0010
_HAS_ARGUMENTS = 0x0020
_HAS_ICON_LOCATION = 0x0040
_IS_UNICODE = 0x0080
_FORCE_NO_LINK_INFO = 0x0100

_STRING_DATA_ORDER = (
    ("name", _HAS_NAME),
    ("relative_path", _HAS_RELATIVE_PATH),
    ("working_directory", _HAS_WORKING_DIR),
    ("arguments", _HAS_ARGUMENTS),
    ("icon_location", _HAS_ICON_LOCATION),
)

_VOLUME_ID_AND_LOCAL_BASE_PATH = 0x0001
_LINK_INFO_UNICODE_HEADER_SIZE = 0x24
_ENVIRONMENT_BLOCK_SIGNATURE = 0xA0000001
_ENVIRONMENT_BLOCK_SIZE = 0x0314
_ENVIRONMENT_ANSI_LENGTH = 260
_MINIMUM_EXTRA_BLOCK_SIZE = 8

_ANSI_ENCODING = "cp1252"
_UNICODE_ENCODING = "utf-16-le"

_SHORTCUT_SUFFIX = ".lnk"


@dataclass(frozen=True, slots=True)
class ShellLink:
    """The fields of a shell link that name the executable it launches."""

    local_base_path: str = ""
    environment_target: str = ""
    relative_path: str = ""
    arguments: str = ""

    def target_path(self, link_directory: PureWindowsPath) -> str:
        """Return the path this link launches, or empty when it names no file."""
        # A link states its target three ways and any one may be the only one
        # present: the LinkInfo base path, an environment block for a target
        # behind %windir%, or RELATIVE_PATH alone, which means nothing until it
        # is joined onto the folder the link itself sits in.
        if self.local_base_path:
            return self.local_base_path
        if self.environment_target:
            return self.environment_target
        if not self.relative_path:
            return ""
        return _join_relative(link_directory, self.relative_path)


def _join_relative(link_directory: PureWindowsPath, relative_path: str) -> str:
    """Collapse a link-relative target onto its folder, or empty when it escapes."""
    resolved: list[str] = list(link_directory.parts)
    for part in PureWindowsPath(relative_path).parts:
        if part == ".":
            continue
        if part == "..":
            if not resolved:
                return ""
            resolved.pop()
        else:
            resolved.append(part)
    return str(PureWindowsPath(*resolved)) if resolved else ""


def _read_null_terminated(data: bytes, offset: int, encoding: str) -> str:
    """Decode the string starting at an offset and running to its terminator."""
    if offset <= 0 or offset >= len(data):
        return ""
    if encoding == _UNICODE_ENCODING:
        end = offset
        while end + 1 < len(data) and data[end : end + 2] != b"\x00\x00":
            end += 2
        return data[offset:end].decode(encoding, "replace")
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode(encoding, "replace")


def _read_link_info(data: bytes, offset: int) -> tuple[str, int]:
    """Read the LinkInfo base path and return it with the offset just past it."""
    info_size, header_size = struct.unpack_from("<II", data, offset)
    if info_size < _MINIMUM_EXTRA_BLOCK_SIZE:
        raise ValueError(f"LinkInfo size {info_size} cannot hold its own header")
    info_flags, _volume_offset, base_offset, _network_offset, suffix_offset = (
        struct.unpack_from("<IIIII", data, offset + 8)
    )
    encoding = _ANSI_ENCODING
    if header_size >= _LINK_INFO_UNICODE_HEADER_SIZE:
        unicode_base_offset, unicode_suffix_offset = struct.unpack_from(
            "<II", data, offset + 28
        )
        if unicode_base_offset:
            base_offset, suffix_offset = unicode_base_offset, unicode_suffix_offset
            encoding = _UNICODE_ENCODING

    base_path = ""
    if info_flags & _VOLUME_ID_AND_LOCAL_BASE_PATH:
        base_path = _read_null_terminated(
            data, offset + base_offset, encoding
        ) + _read_null_terminated(data, offset + suffix_offset, encoding)

    return base_path, offset + info_size


def _read_string_data(
    data: bytes, offset: int, flags: int
) -> tuple[dict[str, str], int]:
    """Read the optional StringData block, in the fixed order the format defines."""
    encoding = _UNICODE_ENCODING if flags & _IS_UNICODE else _ANSI_ENCODING
    width = 2 if flags & _IS_UNICODE else 1
    strings: dict[str, str] = {}
    for field_name, flag in _STRING_DATA_ORDER:
        if not flags & flag:
            continue
        character_count = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        end = offset + character_count * width
        if end > len(data):
            raise ValueError(f"StringData field {field_name} runs past end of link")
        strings[field_name] = data[offset:end].decode(encoding, "replace")
        offset = end
    return strings, offset


def _read_environment_target(data: bytes, offset: int) -> str:
    """Walk the ExtraData blocks for the environment block's target string."""
    target = ""
    while offset + 4 <= len(data):
        block_size = struct.unpack_from("<I", data, offset)[0]
        if block_size < _MINIMUM_EXTRA_BLOCK_SIZE or offset + block_size > len(data):
            break
        signature = struct.unpack_from("<I", data, offset + 4)[0]
        if signature == _ENVIRONMENT_BLOCK_SIGNATURE and (
            block_size >= _ENVIRONMENT_BLOCK_SIZE
        ):
            ansi_target = _read_null_terminated(data, offset + 8, _ANSI_ENCODING)
            unicode_target = _read_null_terminated(
                data, offset + 8 + _ENVIRONMENT_ANSI_LENGTH, _UNICODE_ENCODING
            )
            target = unicode_target or ansi_target
        offset += block_size
    return target


def _parse(data: bytes) -> ShellLink:
    """Walk a shell link's header, LinkInfo, StringData and ExtraData sections."""
    if len(data) < _HEADER_SIZE:
        raise ValueError(
            f"shell link is {len(data)} bytes, header needs {_HEADER_SIZE}"
        )
    header_size = struct.unpack_from("<I", data, 0)[0]
    if header_size != _HEADER_SIZE or data[4:20] != _LINK_CLSID:
        raise ValueError("file does not carry the shell link header and class id")

    flags = struct.unpack_from("<I", data, 20)[0]
    offset = _HEADER_SIZE
    if flags & _HAS_LINK_TARGET_ID_LIST:
        offset += 2 + struct.unpack_from("<H", data, offset)[0]

    # HasLinkInfo alone puts the LinkInfo structure in the byte stream, so it is
    # always read past or StringData would be decoded from inside it.
    # ForceNoLinkInfo only bars using its base path as the target.
    local_base_path = ""
    if flags & _HAS_LINK_INFO:
        link_info_base_path, offset = _read_link_info(data, offset)
        if not flags & _FORCE_NO_LINK_INFO:
            local_base_path = link_info_base_path

    strings, offset = _read_string_data(data, offset, flags)
    return ShellLink(
        local_base_path=local_base_path,
        environment_target=_read_environment_target(data, offset),
        relative_path=strings.get("relative_path", ""),
        arguments=strings.get("arguments", "").strip(),
    )


def parse_shell_link(data: bytes) -> ShellLink:
    """Parse shell link bytes, raising ValueError when they are not a valid link."""
    try:
        return _parse(data)
    except struct.error as error:
        raise ValueError(f"malformed shell link: {error}") from error


def read_shell_link(path: Path) -> ShellLink:
    """Read and parse a shell link file, raising ValueError when it is not one."""
    return parse_shell_link(read_bounded(path, _MAX_SHELL_LINK_BYTES))


def resolve_shortcut_target(
    check_id: str, entry: Path, artifact: str, username: str
) -> tuple[str, str]:
    """Return what a shortcut launches, so the payload is resolved, not the link."""
    if entry.suffix.lower() != _SHORTCUT_SUFFIX:
        return "", ""
    try:
        link = read_shell_link(entry)
    except (OSError, ValueError) as error:
        record_artifact_failure(check_id, entry, error)
        return "", ""
    target = link.target_path(PureWindowsPath(artifact).parent)
    if not target:
        return "", ""
    return canonicalize_windows_path(expand_env_vars(target, username)), (
        link.arguments
    )


def describe_shortcut_entry(entry: Path, target: str, arguments: str) -> str:
    """Name the binary the entry runs, falling back to the file's own name."""
    if not target:
        return entry.name
    return f"{target} {arguments}".strip()
