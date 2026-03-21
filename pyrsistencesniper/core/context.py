"""Central analysis context that binds image paths, hives, and helpers."""

from __future__ import annotations

import enum
import functools
import logging
from pathlib import Path

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.models import HiveProtocol, UserProfile
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import RegistryHelper

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


def _get_active_controlset(
    hive: HiveProtocol,
    registry: RegistryHelper,
) -> str:
    """Read Select\\Current to find the active ControlSet."""
    select_node = registry.load_subtree(hive, "Select")
    current = select_node.get("Current") if select_node else None
    if isinstance(current, int) and current > 0:
        return f"ControlSet{current:03d}"
    for fallback in ("ControlSet001", "ControlSet002"):
        node = registry.load_subtree(
            hive, f"{fallback}\\Control\\ComputerName\\ComputerName"
        )
        if node and node.get("ComputerName"):
            return fallback
    return "ControlSet001"


class AnalysisContext:
    """Central context holding all resolved data for a detection run."""

    def __init__(
        self,
        root: Path,
        hives: dict[str, Path],
        user_profiles: list[UserProfile],
        registry: RegistryHelper,
        filesystem: FilesystemHelper,
        profile: DetectionProfile,
        hostname_override: str = "",
        standalone: bool = False,
    ) -> None:
        self.root = root
        self._hives = hives
        self._profiles = user_profiles
        self.registry = registry
        self.filesystem = filesystem
        self.profile = profile
        self._hostname_override = hostname_override
        self._cached_hostname: str | None = None
        self._standalone = standalone

    def hive_path(self, hive_name: str, username: str = "") -> Path | None:
        """Locate a hive file by name, searching standard Windows paths."""
        name_lower = hive_name.lower()
        if name_lower == "ntuser.dat":
            return self._find_user_hive(hive_name, username)

        if name_lower == "usrclass.dat":
            return self._find_usrclass_hive(hive_name, username)

        # Check discovered hives first
        if name_lower in self._hives:
            return self._hives[name_lower]

        # In standalone mode, only return explicitly discovered hives
        if self._standalone:
            return None

        # Fallback: standard Windows paths
        return self._find_system_hive(hive_name)

    def _find_user_hive(self, hive_name: str, username: str) -> Path | None:
        """Locate an NTUSER.DAT hive under the user's profile directory."""
        if username:
            candidate = self.root / "Users" / username / hive_name
            if candidate.is_file():
                return candidate
        return None

    def _find_usrclass_hive(self, hive_name: str, username: str) -> Path | None:
        """Locate a UsrClass.dat hive under the user's profile directory."""
        if not username:
            return None
        deep = (
            self.root
            / "Users"
            / username
            / "AppData"
            / "Local"
            / "Microsoft"
            / "Windows"
            / hive_name
        )
        if deep.is_file():
            return deep
        shallow = self.root / "Users" / username / hive_name
        return shallow if shallow.is_file() else None

    def _find_system_hive(self, hive_name: str) -> Path | None:
        """Locate a system hive in standard Windows paths."""
        candidate = self.root / "Windows" / "System32" / "config" / hive_name
        if candidate.is_file():
            return candidate
        candidate = self.root / hive_name
        return candidate if candidate.is_file() else None

    @property
    def user_profiles(self) -> list[UserProfile]:
        return self._profiles

    @property
    def hostname(self) -> str:
        """Return the hostname, reading from the SYSTEM hive if not overridden."""
        if self._hostname_override:
            return self._hostname_override
        if self._cached_hostname is not None:
            return self._cached_hostname

        hostname = self._read_hostname_from_system_hive()
        self._cached_hostname = hostname
        return hostname

    @functools.cached_property
    def active_controlset(self) -> str:
        """Return the active ControlSet name, defaulting to ControlSet001."""
        system_path = self.hive_path("SYSTEM")
        if system_path is None:
            return "ControlSet001"
        hive = self.registry.open_hive(system_path)
        if hive is None:
            return "ControlSet001"
        return _get_active_controlset(hive, self.registry)

    def _read_hostname_from_system_hive(self) -> str:
        """Read ComputerName from the SYSTEM hive's active ControlSet."""
        system_path = self.hive_path("SYSTEM")
        if system_path is None:
            return ""
        hive = self.registry.open_hive(system_path)
        if hive is None:
            return ""
        controlset = self.active_controlset
        node = self.registry.load_subtree(
            hive,
            f"{controlset}\\Control\\ComputerName\\ComputerName",
        )
        value = node.get("ComputerName") if node else None
        if value and isinstance(value, str):
            return value
        return ""


def build_context(
    path: Path,
    *,
    hostname: str = "",
    profile: DetectionProfile | None = None,
) -> AnalysisContext:
    """Build an AnalysisContext from a directory or standalone artifact file."""

    resolved = path.resolve()
    kind = _classify_input(resolved)

    if kind == ArtifactKind.HIVE_FILE:
        root, hives, profiles = _build_hive_context(resolved)
        standalone = True
    elif kind == ArtifactKind.EVTX_FILE:
        root, hives, profiles = _build_evtx_context(resolved)
        standalone = True
    else:
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
        profile=profile or DetectionProfile(),
        hostname_override=hostname,
        standalone=standalone,
    )
