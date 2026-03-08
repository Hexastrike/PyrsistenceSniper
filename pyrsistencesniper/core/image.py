from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from pathlib import Path

from pyrsistencesniper.core.registry import RegistryHelper

logger = logging.getLogger(__name__)

_STANDALONE_HIVE_NAMES: frozenset[str] = frozenset(
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


@dataclass(frozen=True, slots=True)
class UserProfile:
    """User profile location within a forensic image."""

    username: str
    profile_path: Path
    ntuser_path: Path | None = None


def _get_active_controlset(
    hive: object,
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


class ForensicImage:
    """Forensic image root with hive access and user enumeration."""

    def __init__(
        self,
        root: Path,
        hostname_override: str = "",
        registry: RegistryHelper | None = None,
    ) -> None:
        self._root = root
        self._hostname_override = hostname_override
        self._cached_hostname: str | None = None
        self._registry = registry or RegistryHelper()

    @property
    def root(self) -> Path:
        return self._root

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
        hive = self._registry.open_hive(system_path)
        if hive is None:
            return "ControlSet001"
        return _get_active_controlset(hive, self._registry)

    def _read_hostname_from_system_hive(self) -> str:
        """Read ComputerName from the SYSTEM hive's active ControlSet."""
        system_path = self.hive_path("SYSTEM")
        if system_path is None:
            return ""
        hive = self._registry.open_hive(system_path)
        if hive is None:
            return ""
        cs = self.active_controlset
        node = self._registry.load_subtree(
            hive, f"{cs}\\Control\\ComputerName\\ComputerName"
        )
        value = node.get("ComputerName") if node else None
        if value and isinstance(value, str):
            return value
        return ""

    @functools.cached_property
    def user_profiles(self) -> list[UserProfile]:
        """Enumerate user profile directories under Users/."""
        users_dir = self._root / "Users"
        profiles: list[UserProfile] = []
        if not users_dir.is_dir():
            return profiles
        try:
            entries = sorted(users_dir.iterdir())
        except PermissionError:
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

    @classmethod
    def is_standalone_artifact(cls, filename: str) -> bool:
        """Return True if the filename matches a known standalone hive name."""
        return filename.lower() in _STANDALONE_HIVE_NAMES

    def hive_path(self, hive_name: str, username: str = "") -> Path | None:
        """Locate a hive file by name, searching standard Windows paths."""
        name_lower = hive_name.lower()
        if name_lower == "ntuser.dat":
            if username:
                candidate = self._root / "Users" / username / hive_name
                if candidate.is_file():
                    return candidate
            return None

        if name_lower == "usrclass.dat":
            if username:
                deep = (
                    self._root
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
                shallow = self._root / "Users" / username / hive_name
                if shallow.is_file():
                    return shallow
            return None

        candidate = self._root / "Windows" / "System32" / "config" / hive_name
        if candidate.is_file():
            return candidate

        candidate = self._root / hive_name
        if candidate.is_file():
            return candidate

        return None
