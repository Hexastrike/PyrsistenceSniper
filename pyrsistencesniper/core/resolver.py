"""Post-detection resolution: file existence, hashing, signer, and classification."""

from __future__ import annotations

import dataclasses
import logging
import re
from typing import Any, TypedDict

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.models import Finding
from pyrsistencesniper.core.signer import SignerExtractor
from pyrsistencesniper.core.windows import (
    canonicalize_windows_path,
    expand_env_vars,
    extract_executable_from_cmdline,
    extract_launcher_from_cmdline,
    is_builtin,
    is_in_os_directory,
    is_lolbin,
)

logger = logging.getLogger(__name__)

_PATH_LIKE_RE = re.compile(r"[\\/]|\.[A-Za-z0-9]{1,4}$")


def _is_path_like(value: str) -> bool:
    """Report whether a value can meaningfully be looked for on disk."""
    # Registry values are often CLSIDs, package names or flags. Recording a miss
    # for one would claim a binary was searched for and absent, which the scan
    # never established.
    return bool(value) and bool(_PATH_LIKE_RE.search(value))


class _CacheEntry(TypedDict):
    """File metadata cached per resolved path so each file is inspected once."""

    exists: bool | None
    sha256: str
    is_lolbin: bool
    is_builtin: bool
    signer: str
    is_in_os_directory: bool


class ResolutionPipeline:
    """Post-detection enrichment of findings."""

    def __init__(self, filesystem: FilesystemHelper) -> None:
        self._fs = filesystem
        self._cache: dict[str, _CacheEntry] = {}
        self._presence: dict[str, bool | None] = {}
        self._signer = SignerExtractor(filesystem)

    # One image is read once: findings repeat their targets, and each probe of
    # a mounted image is a filesystem round trip.
    def _exists(self, path: str) -> bool | None:
        """Report whether the image holds a file at this path, asking it once."""
        key = path.lower()
        if key not in self._presence:
            self._presence[key] = self._fs.exists(path)
        return self._presence[key]

    def _select_target(self, finding: Finding, exe_path: str) -> str:
        """Pick the image path to inspect."""
        # Resolution describes the flagged executable, never the artifact it was
        # found in; a plugin flagging the artifact file itself says so via
        # resolve_target. Otherwise the value-derived executable is inspected
        # even when absent, so a missing binary reports NOT_FOUND rather than
        # silently hashing the artifact the entry was read from.
        if finding.resolve_target:
            return canonicalize_windows_path(finding.resolve_target)

        candidates = [exe_path]
        if "\\" not in exe_path and "." in exe_path:
            candidates.append(f"Windows\\System32\\{exe_path}")
            candidates.append(f"Windows\\{exe_path}")

        for candidate in candidates:
            if candidate and self._exists(candidate):
                return candidate
        return exe_path

    def resolve(self, finding: Finding) -> Finding:
        """Populate resolution fields on a finding, caching results by resolved path."""
        launcher = extract_launcher_from_cmdline(finding.value)
        exe_path = extract_executable_from_cmdline(finding.value)
        if not exe_path:
            exe_path = finding.value
        exe_path = expand_env_vars(exe_path)
        exe_path = canonicalize_windows_path(exe_path)

        resolve_path = self._select_target(finding, exe_path)

        cache_key = resolve_path.lower()
        if cache_key not in self._cache:
            exists = self._exists(resolve_path) if _is_path_like(resolve_path) else None
            self._cache[cache_key] = {
                "exists": exists,
                "sha256": self._fs.sha256(resolve_path) if exists else "",
                "is_lolbin": is_lolbin(resolve_path),
                "is_builtin": is_builtin(resolve_path),
                "signer": (self._signer.extract(resolve_path) if exists else ""),
                "is_in_os_directory": is_in_os_directory(resolve_path),
            }

        cached = self._cache[cache_key]
        replacements: dict[str, Any] = {}

        if finding.exists is None and cached["exists"] is not None:
            replacements["exists"] = cached["exists"]
        if not finding.sha256:
            replacements["sha256"] = cached["sha256"]
        if finding.is_lolbin is None:
            # A payload run through a LOLBin is the technique; classifying only
            # the payload would make adding an argument hide the launcher.
            replacements["is_lolbin"] = cached["is_lolbin"] or (
                bool(launcher) and is_lolbin(launcher)
            )
        if not finding.launcher and launcher:
            replacements["launcher"] = launcher
        if finding.is_builtin is None:
            replacements["is_builtin"] = cached["is_builtin"]
        if finding.is_in_os_directory is None:
            replacements["is_in_os_directory"] = cached["is_in_os_directory"]
        if not finding.signer:
            replacements["signer"] = cached["signer"]

        if replacements:
            return dataclasses.replace(finding, **replacements)
        return finding
