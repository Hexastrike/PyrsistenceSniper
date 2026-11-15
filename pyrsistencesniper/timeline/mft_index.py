"""Lazy $MFT lookup index keyed by normalized image-relative paths."""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import unquote

from pyrsistencesniper.core.filesystem import (
    FilesystemHelper,
    safe_is_dir,
    safe_is_file,
)
from pyrsistencesniper.core.windows import io_path
from pyrsistencesniper.timeline.mft import MftEntry, parse_mft

logger = logging.getLogger(__name__)

_DISCOVERY_DEPTH = 2


def normalize_image_path(windows_path: str) -> str:
    """Reduce a path to a casefolded, drive-less, backslash form for matching."""
    text = windows_path.replace("/", "\\")
    for prefix in ("\\\\?\\", "\\\\.\\"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    if text[1:2] == ":":
        text = text[2:]
    return text.strip("\\").casefold()


class MftIndex:
    """Resolves image paths to their $MFT record timestamps."""

    def __init__(
        self,
        filesystem: FilesystemHelper,
        explicit_path: Path | None = None,
    ) -> None:
        self._fs = filesystem
        self._explicit = explicit_path
        self._entries: dict[str, MftEntry] | None = None

    @property
    def available(self) -> bool:
        """Report whether an $MFT was found and yielded usable records."""
        return bool(self._load())

    def lookup(self, windows_path: str) -> MftEntry | None:
        """Return the $MFT entry for the path, trying a percent-decoded key too."""
        entries = self._load()
        key = normalize_image_path(windows_path)
        hit = entries.get(key)
        if hit is None:
            hit = entries.get(normalize_image_path(unquote(windows_path)))
        return hit

    def _load(self) -> dict[str, MftEntry]:
        """Return the parsed entries, parsing the $MFT on first request."""
        if self._entries is None:
            source = self._explicit or self._discover()
            self._entries = self._parse(source) if source else {}
        return self._entries

    def _parse(self, source: Path) -> dict[str, MftEntry]:
        """Parse an $MFT file into entries keyed by casefolded path."""
        entries: dict[str, MftEntry] = {}
        try:
            with io_path(source).open("rb") as handle:
                for entry in parse_mft(handle):
                    entries[entry.path.casefold()] = entry
        except OSError:
            logger.warning("Cannot read $MFT at %s; MFT evidence disabled", source)
            return {}
        if not entries:
            logger.warning("No usable records in $MFT at %s", source)
        return entries

    def _discover(self) -> Path | None:
        """Look for an $MFT beside the image root, then search below it."""
        root = self._fs.image_root
        for candidate in (root / "$MFT", root.parent / "$MFT"):
            if safe_is_file(candidate):
                return candidate
        return self._scan(root.parent, _DISCOVERY_DEPTH)

    def _scan(self, directory: Path, depth: int) -> Path | None:
        """Search below a directory for an $MFT, files first, to a depth limit."""
        if depth < 0 or not safe_is_dir(directory):
            return None
        try:
            children = sorted(
                directory / child.name for child in io_path(directory).iterdir()
            )
        except OSError:
            logger.debug("Cannot search for $MFT under %s", directory, exc_info=True)
            return None
        for child in children:
            if safe_is_file(child) and unquote(child.name) == "$MFT":
                return child
        for child in children:
            if safe_is_dir(child):
                found = self._scan(child, depth - 1)
                if found is not None:
                    return found
        return None
