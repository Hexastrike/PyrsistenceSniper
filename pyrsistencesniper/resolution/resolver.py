from __future__ import annotations

import dataclasses
import logging
from typing import Any, TypedDict

from pyrsistencesniper.forensics.filesystem import FilesystemHelper
from pyrsistencesniper.forensics.signer import SignerExtractor
from pyrsistencesniper.models.finding import Finding
from pyrsistencesniper.resolution.helpers import _in_system_path, is_builtin, is_lolbin
from pyrsistencesniper.resolution.normalize import (
    canonicalize_windows_path,
    expand_env_vars,
    extract_executable_from_cmdline,
)

logger = logging.getLogger(__name__)


class _CacheEntry(TypedDict):
    exists: bool
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
        self._signer = SignerExtractor(filesystem)

    def resolve(self, finding: Finding) -> Finding:
        """Populate resolution fields on a finding, caching results by resolved path."""
        exe_path = extract_executable_from_cmdline(finding.value)
        if not exe_path:
            exe_path = finding.value
        exe_path = expand_env_vars(exe_path)
        exe_path = canonicalize_windows_path(exe_path)

        # Bare filenames (e.g. "ifmon.dll") fall back to System32
        resolve_path = exe_path
        if "\\" not in exe_path and "." in exe_path:
            sys32_path = f"Windows\\System32\\{exe_path}"
            sys32_key = sys32_path.lower()
            if sys32_key in self._cache or self._fs.exists(sys32_path):
                resolve_path = sys32_path

        cache_key = resolve_path.lower()
        if cache_key not in self._cache:
            exists = self._fs.exists(resolve_path)
            self._cache[cache_key] = {
                "exists": exists,
                "sha256": self._fs.sha256(resolve_path) if exists else "",
                "is_lolbin": is_lolbin(resolve_path),
                "is_builtin": is_builtin(resolve_path),
                "signer": (self._signer.extract(resolve_path) if exists else ""),
                "is_in_os_directory": _in_system_path(resolve_path),
            }

        cached = self._cache[cache_key]
        replacements: dict[str, Any] = {}

        if finding.exists is None:
            replacements["exists"] = cached["exists"]
        if not finding.sha256:
            replacements["sha256"] = cached["sha256"]
        if finding.is_lolbin is None:
            replacements["is_lolbin"] = cached["is_lolbin"]
        if finding.is_builtin is None:
            replacements["is_builtin"] = cached["is_builtin"]
        if finding.is_in_os_directory is None:
            replacements["is_in_os_directory"] = cached["is_in_os_directory"]
        if not finding.signer:
            replacements["signer"] = cached["signer"]

        if replacements:
            return dataclasses.replace(finding, **replacements)
        return finding
