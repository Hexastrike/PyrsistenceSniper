"""Discovery and classification helpers for forensic artifacts."""

from __future__ import annotations

import enum
import logging
from pathlib import Path

from pyrsistencesniper.models.finding import UserProfile

logger = logging.getLogger(__name__)


class ArtifactKind(enum.Enum):
    IMAGE_ROOT = "image_root"
    HIVE_FILE = "hive_file"
    EVTX_FILE = "evtx_file"


_KNOWN_HIVE_NAMES: frozenset[str] = frozenset(
    {
        "software",
        "system",
        "sam",
        "security",
        "ntuser.dat",
        "usrclass.dat",
        "default",
        "amcache.hve",
    }
)


def _classify_input(resolved: Path) -> ArtifactKind:
    """Classify a resolved path as an image root, hive file, or evtx file."""
    if not resolved.is_file():
        return ArtifactKind.IMAGE_ROOT
    name = resolved.name.lower()
    if name in _KNOWN_HIVE_NAMES:
        return ArtifactKind.HIVE_FILE
    if name.endswith(".evtx"):
        return ArtifactKind.EVTX_FILE
    return ArtifactKind.IMAGE_ROOT


def is_known_artifact(filename: str) -> bool:
    """Return True if the filename matches a known standalone artifact name."""
    name = filename.lower()
    return name in _KNOWN_HIVE_NAMES or name.endswith(".evtx")


def _build_hive_context(
    resolved: Path,
) -> tuple[Path, dict[str, Path], list[UserProfile]]:
    """Set up root, hives, and profiles for a standalone hive file."""
    root = resolved.parent
    name = resolved.name.lower()
    if name in ("ntuser.dat", "usrclass.dat"):
        hives: dict[str, Path] = {}
        profiles = [
            UserProfile(
                "standalone_user",
                root,
                resolved if name == "ntuser.dat" else None,
            )
        ]
    else:
        hives = {name: resolved}
        profiles = []
    return root, hives, profiles


def _build_evtx_context(
    resolved: Path,
) -> tuple[Path, dict[str, Path], list[UserProfile]]:
    """Set up root, hives, and profiles for a standalone evtx file."""
    return resolved.parent, {}, []


def _discover_hives(root: Path) -> dict[str, Path]:
    """Search Windows/System32/config/ then root fallback."""
    hives: dict[str, Path] = {}
    config_dir = root / "Windows" / "System32" / "config"
    if config_dir.is_dir():
        try:
            for entry in config_dir.iterdir():
                if entry.is_file():
                    hives[entry.name.lower()] = entry
        except PermissionError:
            logger.debug("Permission denied reading %s", config_dir)
    # Root-level fallback for hives not found in config/
    try:
        for entry in root.iterdir():
            if (
                entry.is_file()
                and entry.name.lower() not in hives
                and entry.name.lower() in _KNOWN_HIVE_NAMES
            ):
                hives[entry.name.lower()] = entry
    except PermissionError:
        logger.debug("Permission denied reading %s", root)
    return hives


def _discover_profiles(root: Path) -> list[UserProfile]:
    """Enumerate user profiles under root/Users/."""
    users_dir = root / "Users"
    profiles: list[UserProfile] = []
    if not users_dir.is_dir():
        return profiles
    try:
        entries = sorted(users_dir.iterdir())
    except PermissionError:
        logger.debug("Permission denied reading %s", users_dir)
        return profiles
    for entry in entries:
        if not entry.is_dir():
            continue
        ntuser = entry / "NTUSER.DAT"
        profiles.append(
            UserProfile(
                username=entry.name,
                profile_path=entry,
                ntuser_path=ntuser if ntuser.is_file() else None,
            )
        )
    return profiles
