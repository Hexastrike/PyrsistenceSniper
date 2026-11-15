"""Scan ledger: what one scan could not read, kept so its silence is reportable."""

from __future__ import annotations

import errno
import logging
from pathlib import Path

from pyrsistencesniper.core.models import CheckFailure

logger = logging.getLogger(__name__)

# One scan's lost coverage, so a report can tell "found nothing here" from
# "could not look here". build_context() resets it, and that reset is what
# scopes it to a scan: nothing an earlier scan lost can leak into the next
# report.
_skipped: dict[str, str] = {}
_check_failures: dict[str, CheckFailure] = {}
_partial_reads: dict[str, str] = {}
_artifact_failures: dict[str, CheckFailure] = {}


def reset() -> None:
    """Forget everything an earlier scan recorded."""
    for records in (_skipped, _check_failures, _partial_reads, _artifact_failures):
        records.clear()


def describe_failure(reason: BaseException | str) -> str:
    """Render a failure as the single line a report can carry."""
    if isinstance(reason, BaseException):
        return f"{type(reason).__name__}: {reason}"
    return str(reason)


def record_skip(path: Path, error: OSError) -> None:
    """Note a path the scan could not read."""
    _skipped[str(path)] = describe_failure(error)


def skipped_paths() -> dict[str, str]:
    """Return the paths this scan could not read, mapped to the error each gave."""
    return dict(_skipped)


def record_check_failure(check_id: str, reason: BaseException | str) -> None:
    """Note a check or plugin module that raised and so produced nothing."""
    _check_failures[check_id] = CheckFailure(
        check_id=check_id, error=describe_failure(reason)
    )


def record_partial_read(key_name: str, reason: BaseException | str) -> bool:
    """Note a registry key read only in part, reporting False when already noted."""
    if key_name in _partial_reads:
        return False
    _partial_reads[key_name] = describe_failure(reason)
    return True


def partial_reads() -> dict[str, str]:
    """Return the registry keys that could only be read in part, mapped to why."""
    return dict(_partial_reads)


def record_artifact_failure(
    check_id: str, artifact: Path | str, reason: BaseException | str
) -> None:
    """Note an artifact that exists but would not parse, so its silence is reported."""
    # An artifact the image never held is a real negative, not coverage the scan lost.
    if isinstance(reason, OSError) and reason.errno in (errno.ENOENT, errno.ENOTDIR):
        return
    failure = CheckFailure(
        check_id=check_id, artifact=str(artifact), error=describe_failure(reason)
    )
    if failure.label in _artifact_failures:
        return
    _artifact_failures[failure.label] = failure
    logger.warning(
        "Check %s could not read artifact %s: %s", check_id, artifact, failure.error
    )


def artifact_failures() -> tuple[CheckFailure, ...]:
    """Return the artifacts a check found but could not parse, as coverage it lost."""
    return tuple(_artifact_failures[label] for label in sorted(_artifact_failures))


def failures() -> tuple[CheckFailure, ...]:
    """Return everything that produced nothing: checks, then keys, then artifacts."""
    keys = tuple(
        CheckFailure(artifact=f"registry key {key_name}", error=error)
        for key_name, error in sorted(_partial_reads.items())
    )
    return (*_check_failures.values(), *keys, *artifact_failures())
