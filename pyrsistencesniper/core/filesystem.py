"""Filesystem helpers for resolving Windows paths and inspecting files."""

from __future__ import annotations

import errno
import functools
import hashlib
import logging
import os
from pathlib import Path, PureWindowsPath

from pyrsistencesniper.core.windows import (
    _io_path,
    _on_windows,
    canonicalize_windows_path,
    is_representable_windows_path,
)

logger = logging.getLogger(__name__)

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# Paths this scan could not read, mapped to why. Reset per scan by reset_skips().
_skipped: dict[str, str] = {}


def reset_skips() -> None:
    """Forget the skips recorded by an earlier scan."""
    _skipped.clear()


def skipped_paths() -> dict[str, str]:
    """Return the paths this scan could not read, mapped to the error each gave."""
    return dict(_skipped)


def _is_reparse_point(path: Path) -> bool:
    """Report whether a path is a reparse point, without opening it."""
    # A junction or symlink on a mounted image routinely refuses to open while
    # its target stays enumerable under its real name, so failing to read one
    # costs no coverage. The attribute lives in the parent's directory index,
    # which is why this never touches the entry itself.
    if not _on_windows():
        return False
    try:
        with os.scandir(_io_path(path.parent)) as entries:
            for entry in entries:
                if entry.name.lower() == path.name.lower():
                    attributes = getattr(
                        entry.stat(follow_symlinks=False), "st_file_attributes", 0
                    )
                    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return False
    return False


def _record_skip(path: Path, error: OSError) -> None:
    """Note an unreadable path, at the level its cause deserves."""
    if error.errno in (errno.ENOENT, errno.ENOTDIR):
        return
    if _is_reparse_point(path):
        logger.debug("Reparse point will not open, target read separately: %s", path)
        return
    logger.debug("Cannot read %s", path, exc_info=True)
    _skipped[str(path)] = f"{type(error).__name__}: {error}"


def safe_is_file(path: Path) -> bool | None:
    """Report whether a path is a file, or None when that cannot be determined."""
    # None and False mean different things: a file the scan could not look at
    # versus one the image does not contain. Collapsing them would let an
    # unreadable path be reported as evidence of absence.
    try:
        return _io_path(path).is_file()
    except OSError as error:
        _record_skip(path, error)
        return None


def safe_is_dir(path: Path) -> bool | None:
    """Report whether a path is a directory, or None when undeterminable."""
    try:
        return _io_path(path).is_dir()
    except OSError as error:
        _record_skip(path, error)
        return None


def safe_exists(path: Path) -> bool | None:
    """Report whether a path exists at all, or None when undeterminable."""
    try:
        return _io_path(path).exists()
    except OSError as error:
        _record_skip(path, error)
        return None


def safe_iterdir(directory: Path) -> list[Path]:
    """List directory entries, returning empty list on any OS error."""
    try:
        # Children of a prefixed directory carry the prefix; rebuild them under
        # the caller's path so it never leaks into logs or comparisons.
        return [directory / child.name for child in _io_path(directory).iterdir()]
    except OSError as error:
        # No traceback here: _record_skip logs one where the cause warrants it,
        # and a directory that is merely absent does not warrant one at all.
        logger.debug("Cannot read directory: %s", directory)
        _record_skip(directory, error)
        return []


class FilesystemHelper:
    """Resolves Windows paths to host paths and inspects files under the image root."""

    def __init__(self, image_root: Path) -> None:
        self._root = image_root

    @property
    def image_root(self) -> Path:
        """Return the image root every resolved path stays under."""
        return self._root

    # Resolved once: every lookup compares against it, and resolving it per
    # call doubled the filesystem round trips of a scan.
    @functools.cached_property
    def _resolved_root(self) -> Path | None:
        """Return the image root with links followed, or None when it cannot be."""
        try:
            return self._root.resolve()
        except (OSError, ValueError):
            logger.debug("Unresolvable image root: %s", self._root, exc_info=True)
            return None

    def resolve(self, windows_path: str) -> Path:
        """Map a Windows path to an absolute host path under the image root."""
        # Values come from untrusted images and can be oversized or contain NUL,
        # which the platform rejects outright. Such a value resolves to the image
        # root rather than raising, so one poisoned artifact cannot end the scan.
        canonical = canonicalize_windows_path(windows_path)
        if not canonical:
            return self._root
        if not is_representable_windows_path(canonical):
            # Truncated: logging the whole value is the amplification this guards.
            logger.debug("Path longer than Windows allows: %s", canonical[:80])
            return self._root
        root = self._resolved_root
        if root is None:
            return self._root
        try:
            joined = (self._root / PureWindowsPath(canonical)).resolve()
        except (OSError, ValueError):
            logger.debug("Unresolvable path: %s", windows_path, exc_info=True)
            return self._root
        if not joined.is_relative_to(root):
            logger.warning("Path escapes image root, ignoring: %s", windows_path)
            return self._root
        return joined

    def image_relative(self, host_path: Path) -> str:
        """Return a host path as the Windows path it occupies inside the image."""
        try:
            return str(PureWindowsPath(host_path.relative_to(self._root)))
        except ValueError:
            # A path from outside the image is still the best identity a
            # finding has, so it is reported whole rather than dropped.
            logger.debug(
                "Path not relative to image root: %s", host_path, exc_info=True
            )
            return str(host_path)

    def exists(self, windows_path: str) -> bool | None:
        """Report whether the resolved path is a file, None when it cannot be read."""
        # Absence is evidence downstream; an unreadable path is not evidence of it.
        return safe_is_file(self.resolve(windows_path))

    def sha256(self, windows_path: str) -> str:
        """Return the hex SHA-256 digest of the file, or empty string on error."""
        resolved = self.resolve(windows_path)
        try:
            hasher = hashlib.sha256()
            with _io_path(resolved).open("rb") as file_handle:
                for chunk in iter(lambda: file_handle.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            logger.debug("SHA-256 skipped, file not in collection: %s", resolved)
            return ""
        except OSError:
            logger.debug("SHA-256 failed for %s", resolved, exc_info=True)
            return ""
