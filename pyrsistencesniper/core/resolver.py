"""Post-detection resolution: file existence, hashing, signer, and classification."""

from __future__ import annotations

import dataclasses
import logging
import re
from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class _FileFacts:
    """What the image says about one target, gathered once per path."""

    exists: bool | None
    sha256: str
    signer: str
    is_lolbin: bool
    is_builtin: bool
    is_in_os_directory: bool


class ResolutionPipeline:
    """Post-detection enrichment of findings."""

    def __init__(self, filesystem: FilesystemHelper) -> None:
        self._fs = filesystem
        self._facts_by_path: dict[str, _FileFacts] = {}
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

    def _facts(self, path: str) -> _FileFacts:
        """Inspect a target once and remember what the image said about it."""
        key = path.lower()
        if key not in self._facts_by_path:
            exists = self._exists(path) if _is_path_like(path) else None
            self._facts_by_path[key] = _FileFacts(
                exists=exists,
                sha256=self._fs.sha256(path) if exists else "",
                signer=self._signer.extract(path) if exists else "",
                is_lolbin=is_lolbin(path),
                is_builtin=is_builtin(path),
                is_in_os_directory=is_in_os_directory(path),
            )
        return self._facts_by_path[key]

    def resolve(self, finding: Finding) -> Finding:
        """Return the finding with its resolution fields filled from the image."""
        launcher = extract_launcher_from_cmdline(finding.value)
        exe_path = extract_executable_from_cmdline(finding.value) or finding.value
        exe_path = canonicalize_windows_path(expand_env_vars(exe_path))
        facts = self._facts(self._select_target(finding, exe_path))
        return dataclasses.replace(
            finding,
            exists=facts.exists,
            sha256=facts.sha256,
            signer=facts.signer,
            is_builtin=facts.is_builtin,
            is_in_os_directory=facts.is_in_os_directory,
            launcher=launcher,
            # A payload run through a LOLBin is the technique; classifying only
            # the payload would make adding an argument hide the launcher.
            is_lolbin=facts.is_lolbin or (bool(launcher) and is_lolbin(launcher)),
        )
