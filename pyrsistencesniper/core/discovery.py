from __future__ import annotations

import logging
from pathlib import Path

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.forensics.filesystem import FilesystemHelper
from pyrsistencesniper.forensics.registry import RegistryHelper
from pyrsistencesniper.models.finding import UserProfile

logger = logging.getLogger(__name__)


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
                and AnalysisContext.is_standalone_artifact(entry.name)
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


def build_context(
    path: Path,
    *,
    hostname: str = "",
    profile: DetectionProfile | None = None,
) -> AnalysisContext:
    """Build an AnalysisContext from a directory or standalone artifact file."""
    resolved = path.resolve()

    if resolved.is_file() and AnalysisContext.is_standalone_artifact(resolved.name):
        # Standalone mode: single file, no discovery
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
        standalone = True
    else:
        # Image root mode: full discovery
        root = resolved
        hives = _discover_hives(root)
        profiles = _discover_profiles(root)
        standalone = False

    return AnalysisContext(
        root=root,
        hives=hives,
        user_profiles=profiles,
        registry=RegistryHelper(),
        filesystem=FilesystemHelper(image_root=root),
        profile=profile or DetectionProfile.default(),
        hostname_override=hostname,
        standalone=standalone,
    )
