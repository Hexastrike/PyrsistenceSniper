"""Filesystem helpers for resolving Windows paths and inspecting files."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path, PureWindowsPath

from pyrsistencesniper.resolution.normalize import canonicalize_windows_path

logger = logging.getLogger(__name__)


class FilesystemHelper:
    """Resolves Windows paths to host paths and inspects files under the image root."""

    def __init__(self, image_root: Path) -> None:
        self._root = image_root

    @property
    def image_root(self) -> Path:
        return self._root

    def resolve(self, windows_path: str) -> Path:
        """Map a Windows path to an absolute host path under the image root."""
        canonical = canonicalize_windows_path(windows_path)
        if not canonical:
            return self._root
        joined = (self._root / PureWindowsPath(canonical)).resolve()
        root = self._root.resolve()
        if not joined.is_relative_to(root):
            logger.warning("Path escapes image root, ignoring: %s", windows_path)
            return self._root
        return joined

    def exists(self, windows_path: str) -> bool:
        """Return True if the resolved path points to an existing file."""
        return self.resolve(windows_path).is_file()

    def sha256(self, windows_path: str) -> str:
        """Return the hex SHA-256 digest of the file, or empty string on error."""
        resolved = self.resolve(windows_path)
        try:
            hasher = hashlib.sha256()
            with resolved.open("rb") as file_handle:
                for chunk in iter(lambda: file_handle.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except OSError:
            logger.debug("SHA-256 failed for %s", resolved, exc_info=True)
            return ""
