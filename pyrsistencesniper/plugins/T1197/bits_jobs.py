"""Detect BITS jobs that carry a notification command line (T1197)."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
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

_DOWNLOADER_DIRECTORY = Path("ProgramData") / "Microsoft" / "Network" / "Downloader"
_STATE_FILES: tuple[Path, ...] = (
    _DOWNLOADER_DIRECTORY / "qmgr.db",
    _DOWNLOADER_DIRECTORY / "qmgr0.dat",
    _DOWNLOADER_DIRECTORY / "qmgr1.dat",
)

# The queue manager serialises each job as a 16-byte job id followed by counted
# UTF-16 strings: display name, description, notification program, notification
# parameters, owner SID. The owner SID is the anchor rather than any file-format
# magic, because the same record shape is what BITS writes into the ESE database
# of Windows 10 and later and into the legacy qmgr*.dat queues. The four fields
# before it are walked backwards.
_FIELDS_BEFORE_OWNER = 4
_JOB_ID_SIZE = 16
# The shortest field a record can hold: a four-byte length and a bare terminator.
_MIN_FIELD_BYTES = 6
_UTF16_TERMINATOR = b"\x00\x00"
_OWNER_SID_PATTERN = re.compile(rb"S\x00-\x001\x00-\x00")

# No BITS string approaches this, and staying below 65536 is what makes the
# backward walk unambiguous: the high half of a length field is always zero.
_MAX_STRING_CHARS = 8192

# The state file is read in overlapping windows, so a large one costs the scan
# time but not memory. The overlap exceeds the longest record a scan can read.
_WINDOW_BYTES = 4 * 1024 * 1024
_OVERLAP_BYTES = 256 * 1024
_MAX_JOBS = 10_000

_SYSTEM_OWNER_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})


@dataclass(frozen=True, slots=True)
class _BitsJob:
    """One BITS job recovered from the queue manager's state file."""

    job_id: str = ""
    display_name: str = ""
    program: str = ""
    parameters: str = ""
    owner: str = ""


def _counted_string_at(data: bytes, length_offset: int) -> str | None:
    """Read the counted UTF-16 string whose length field starts at an offset."""
    if length_offset < 0 or length_offset + 4 > len(data):
        return None
    length: int = struct.unpack_from("<I", data, length_offset)[0]
    if length < 1 or length > _MAX_STRING_CHARS:
        return None
    end = length_offset + 4 + 2 * length
    if end > len(data):
        return None
    raw = data[length_offset + 4 : end]
    if raw[-2:] != _UTF16_TERMINATOR:
        return None
    text = raw[:-2].decode("utf-16-le", "replace")
    if "\x00" in text:
        return None
    return text


def _counted_string_before(data: bytes, end: int) -> tuple[str, int] | None:
    """Read the counted string ending at an offset, and where its length field is."""
    if end < _MIN_FIELD_BYTES or data[end - 2 : end] != _UTF16_TERMINATOR:
        return None
    position = end - 4
    limit = max(0, end - 2 * _MAX_STRING_CHARS)
    while position >= limit and data[position : position + 2] != _UTF16_TERMINATOR:
        position -= 2
    if position < limit:
        return None
    length_offset = position - 2
    text = _counted_string_at(data, length_offset)
    if text is None or len(text) + 1 != (end - length_offset - 4) // 2:
        return None
    return text, length_offset


def _format_job_id(raw: bytes) -> str:
    """Render the 16 bytes preceding a job record as its GUID."""
    first, second, third = struct.unpack_from("<IHH", raw, 0)
    node = raw[8:]
    return (
        f"{{{first:08X}-{second:04X}-{third:04X}-"
        f"{node[:2].hex().upper()}-{node[2:].hex().upper()}}}"
    )


def _job_before_owner(data: bytes, owner_start: int) -> _BitsJob | None:
    """Recover the job record whose owner SID string begins at an offset."""
    owner = _counted_string_at(data, owner_start - 4)
    if owner is None:
        return None
    fields: list[str] = []
    end = owner_start - 4
    for _ in range(_FIELDS_BEFORE_OWNER):
        recovered = _counted_string_before(data, end)
        if recovered is None:
            return None
        text, end = recovered
        fields.append(text)
    if end < _JOB_ID_SIZE:
        return None
    parameters, program, _description, display_name = fields
    return _BitsJob(
        job_id=_format_job_id(data[end - _JOB_ID_SIZE : end]),
        display_name=display_name,
        program=program,
        parameters=parameters,
        owner=owner,
    )


def _iter_jobs(data: bytes) -> Iterator[_BitsJob]:
    """Yield every job record whose owner SID and preceding fields validate."""
    for match in _OWNER_SID_PATTERN.finditer(data):
        job = _job_before_owner(data, match.start())
        if job is not None:
            yield job


def _iter_windows(handle: BinaryIO) -> Iterator[bytes]:
    """Yield overlapping windows so a record on a boundary is still read whole."""
    window = handle.read(_WINDOW_BYTES)
    while window:
        yield window
        block = handle.read(_WINDOW_BYTES)
        if not block:
            return
        window = window[-_OVERLAP_BYTES:] + block


def _notification_command(job: _BitsJob) -> str:
    """Render the command BITS runs for a job, or empty when it sets none."""
    program = job.program.strip()
    if not program:
        return ""
    parameters = job.parameters.strip()
    if not parameters or parameters.lower().startswith(program.lower()):
        return parameters or program
    return f"{program} {parameters}"


@register_plugin
class BitsNotifyCommand(PersistencePlugin):
    """Detects BITS jobs carrying a notification command line."""

    definition = CheckDefinition(
        id="bits_notify_command",
        technique="BITS Job Notification Command",
        mitre_id="T1197",
        description=(
            "A BITS job can carry a notification command line that the queue manager "
            "runs when the transfer completes or finally fails. The job survives "
            "reboots and lives in no registry key and no scheduled task."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every BITS job whose record carries a notification command."""
        findings: list[Finding] = []
        for state_relative in _STATE_FILES:
            state_path = self.filesystem.image_root / state_relative
            if not safe_is_file(state_path):
                continue
            state_display = str(PureWindowsPath(state_relative))
            for job in self._read_jobs(state_path):
                command = _notification_command(job)
                if command:
                    findings.append(self._describe(job, state_display, command))
        return findings

    def _describe(self, job: _BitsJob, state_display: str, command: str) -> Finding:
        """Report one job's notification command as the payload it runs."""
        return self._make_finding(
            path=f"{state_display}\\{job.job_id}",
            value=command,
            access=(
                AccessLevel.SYSTEM
                if job.owner in _SYSTEM_OWNER_SIDS
                else AccessLevel.USER
            ),
            resolve_target=job.program,
            time_evidence=(FileWriteTime(path=state_display, weak=True),),
        )

    def _read_jobs(self, state_path: Path) -> list[_BitsJob]:
        """Stream the state file so its size costs the scan time but not memory."""
        jobs: list[_BitsJob] = []
        already_seen: set[tuple[str, str, str]] = set()
        try:
            with _io_path(state_path).open("rb") as handle:
                for window in _iter_windows(handle):
                    for job in _iter_jobs(window):
                        identity = (job.job_id, job.program, job.parameters)
                        if identity in already_seen:
                            continue
                        already_seen.add(identity)
                        jobs.append(job)
                        if len(jobs) >= _MAX_JOBS:
                            record_artifact_failure(
                                self.definition.id,
                                state_path,
                                f"stopped after {_MAX_JOBS} job records; the rest "
                                f"of the queue was not examined",
                            )
                            return jobs
        except (OSError, MemoryError) as exc:
            record_artifact_failure(self.definition.id, state_path, exc)
        return jobs
