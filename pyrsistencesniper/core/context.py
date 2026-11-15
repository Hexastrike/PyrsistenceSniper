"""Artifact discovery and the analysis context binding hives, files, and helpers."""

from __future__ import annotations

import dataclasses
import enum
import functools
import logging
from collections.abc import Iterator
from pathlib import Path

from pyrsistencesniper.core import ledger
from pyrsistencesniper.core.filesystem import (
    FilesystemHelper,
    safe_exists,
    safe_is_dir,
    safe_is_file,
    safe_iterdir,
)
from pyrsistencesniper.core.models import (
    HiveProtocol,
    HiveRecord,
    HiveStatus,
    UserProfile,
)
from pyrsistencesniper.core.registry import (
    RegistryHelper,
    RegistryNode,
    hive_key,
)

logger = logging.getLogger(__name__)

_DEFAULT_CONTROLSET = "ControlSet001"
_PROFILE_LIST_KEY = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"

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

_USER_HIVE_NAMES: frozenset[str] = frozenset({"ntuser.dat", "usrclass.dat"})

_MACHINE_CLASS_ROOTS: tuple[str, ...] = ("Classes", "Classes\\Wow6432Node")

__all__ = [
    "AnalysisContext",
    "ArtifactKind",
    "UnsupportedArtifactError",
    "build_context",
    "classify_input",
    "discover_hives",
    "discover_profiles",
]


class ArtifactKind(enum.Enum):
    """Kind of scan target supplied on the command line."""

    IMAGE_ROOT = "image_root"
    HIVE_FILE = "hive_file"


class UnsupportedArtifactError(ValueError):
    """Raised when the scan target is a file that is not a supported hive."""


def classify_input(resolved: Path) -> ArtifactKind:
    """Classify a resolved path as an image root or a standalone hive file."""
    # Any other file is rejected outright: scanning it silently would produce an
    # empty report that an analyst could mistake for a clean result.
    if not safe_is_file(resolved):
        return ArtifactKind.IMAGE_ROOT
    if resolved.name.lower() in _KNOWN_HIVE_NAMES:
        return ArtifactKind.HIVE_FILE
    supported = ", ".join(sorted(_KNOWN_HIVE_NAMES))
    raise UnsupportedArtifactError(
        f"'{resolved.name}' is not a supported registry hive. "
        f"Pass an image root directory or one of: {supported}"
    )


def build_hive_context(
    resolved: Path,
) -> tuple[Path, dict[str, Path], list[UserProfile]]:
    """Set up root, hives, and profiles for a standalone hive file."""
    root = resolved.parent
    name = resolved.name.lower()
    if name in _USER_HIVE_NAMES:
        hives: dict[str, Path] = {}
        profiles = [
            UserProfile(
                username="standalone_user",
                profile_path=root,
                ntuser_path=resolved if name == "ntuser.dat" else None,
                usrclass_path=resolved if name == "usrclass.dat" else None,
            )
        ]
    else:
        hives = {name: resolved}
        profiles = []
    return root, hives, profiles


def discover_hives(root: Path) -> dict[str, Path]:
    """Search Windows/System32/config/ then root fallback for known hive files."""
    hives: dict[str, Path] = {}
    config_dir = root / "Windows" / "System32" / "config"
    if safe_is_dir(config_dir):
        for entry in safe_iterdir(config_dir):
            name = entry.name.lower()
            if safe_is_file(entry) and name in _KNOWN_HIVE_NAMES:
                hives[name] = entry
    for entry in safe_iterdir(root):
        name = entry.name.lower()
        if safe_is_file(entry) and name not in hives and name in _KNOWN_HIVE_NAMES:
            hives[name] = entry
    return hives


def discover_profiles(root: Path) -> list[UserProfile]:
    """Enumerate user profiles under root/Users/, with NTUSER.DAT and UsrClass.dat."""
    users_dir = root / "Users"
    profiles: list[UserProfile] = []
    if not safe_is_dir(users_dir):
        return profiles
    for entry in sorted(safe_iterdir(users_dir)):
        if not safe_is_dir(entry):
            continue
        ntuser = entry / "NTUSER.DAT"
        usrclass_deep = (
            entry / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
        )
        usrclass_shallow = entry / "UsrClass.dat"
        if safe_is_file(usrclass_deep):
            usrclass_path: Path | None = usrclass_deep
        elif safe_is_file(usrclass_shallow):
            usrclass_path = usrclass_shallow
        else:
            usrclass_path = None
        profiles.append(
            UserProfile(
                username=entry.name,
                profile_path=entry,
                ntuser_path=ntuser if safe_is_file(ntuser) else None,
                usrclass_path=usrclass_path,
            )
        )
    return profiles


class AnalysisContext:
    """Bind the hives, profiles and helpers one detection run reads from."""

    def __init__(
        self,
        root: Path,
        hives: dict[str, Path],
        user_profiles: list[UserProfile],
        registry: RegistryHelper,
        filesystem: FilesystemHelper,
        hostname_override: str = "",
        standalone: bool = False,
    ) -> None:
        self.root = root
        self._hives = hives
        self._profiles = user_profiles
        self.registry = registry
        self.filesystem = filesystem
        self._hostname_override = hostname_override
        self._standalone = standalone

    def hive_path(self, hive_name: str, username: str = "") -> Path | None:
        """Locate a hive file by name, using the paths found during discovery."""
        name_lower = hive_name.lower()
        if name_lower == "ntuser.dat":
            return self._profile_hive(username, usrclass=False)
        if name_lower == "usrclass.dat":
            return self._profile_hive(username, usrclass=True)
        return self._hives.get(name_lower)

    def _profile_hive(self, username: str, *, usrclass: bool) -> Path | None:
        """Return a discovered per-user hive path for the named profile."""
        if not username:
            return None
        for profile in self._profiles:
            if profile.username == username:
                return profile.usrclass_path if usrclass else profile.ntuser_path
        return None

    @property
    def user_profiles(self) -> list[UserProfile]:
        """Return the user profiles discovered under the image root."""
        return self._profiles

    @property
    def standalone(self) -> bool:
        """Report whether the scan target was a single standalone hive file."""
        return self._standalone

    @functools.cached_property
    def hostname(self) -> str:
        """Return the hostname, reading from the SYSTEM hive if not overridden."""
        if self._hostname_override:
            return self._hostname_override
        hive = self.open_hive_by_name("SYSTEM")
        if hive is None:
            return ""
        node = self.registry.load_subtree(
            hive,
            f"{self.active_controlset}\\Control\\ComputerName\\ComputerName",
        )
        value = node.get("ComputerName") if node else None
        return value if isinstance(value, str) and value else ""

    @functools.cached_property
    def active_controlset(self) -> str:
        """Return the active ControlSet name, defaulting to ControlSet001."""
        hive = self.open_hive_by_name("SYSTEM")
        if hive is None:
            return _DEFAULT_CONTROLSET
        select_node = self.registry.load_subtree(hive, "Select")
        current = select_node.get("Current") if select_node else None
        if isinstance(current, int) and current > 0:
            return f"ControlSet{current:03d}"
        for fallback in ("ControlSet001", "ControlSet002"):
            node = self.registry.load_subtree(
                hive, f"{fallback}\\Control\\ComputerName\\ComputerName"
            )
            if node and node.get("ComputerName"):
                return fallback
        return _DEFAULT_CONTROLSET

    @functools.cached_property
    def profile_sids(self) -> dict[str, str]:
        """Map each casefolded profile directory name to its account SID."""
        # ProfileList keys by SID and stores the profile directory in
        # ProfileImagePath, the only link between the ``Users\\<name>``
        # directory an offline scan walks and the SID a live system logs under.
        # Resolved on demand so a scan that never needs it does not open SOFTWARE.
        hive = self.open_hive_by_name("SOFTWARE")
        if hive is None:
            return {}
        node = self.registry.load_subtree(hive, _PROFILE_LIST_KEY)
        if node is None:
            return {}
        sids: dict[str, str] = {}
        for sid, child in node.children():
            image_path = child.get("ProfileImagePath")
            if not isinstance(image_path, str) or not image_path.strip():
                continue
            directory = image_path.replace("/", "\\").rstrip("\\").rpartition("\\")[2]
            if directory:
                sids.setdefault(directory.casefold(), sid)
        return sids

    def open_hive_by_name(self, hive_name: str) -> HiveProtocol | None:
        """Resolve and open a registry hive by name. Returns None on failure."""
        hive_path = self.hive_path(hive_name)
        if hive_path is None:
            return None
        return self.registry.open_hive(hive_path)

    def load_subtree(self, hive_name: str, key_path: str) -> RegistryNode | None:
        """Open a hive and return a RegistryNode for the given key path."""
        hive = self.open_hive_by_name(hive_name)
        if hive is None:
            return None
        return self.registry.load_subtree(hive, key_path)

    def iter_user_hives(self) -> Iterator[tuple[UserProfile, HiveProtocol]]:
        """Iterate over user profiles, yielding each with its opened NTUSER hive."""
        yield from self._iter_profile_hives(usrclass=False)

    def iter_usrclass_hives(self) -> Iterator[tuple[UserProfile, HiveProtocol]]:
        """Iterate user profiles, yielding each with its opened UsrClass.dat hive."""
        yield from self._iter_profile_hives(usrclass=True)

    def _iter_profile_hives(
        self, *, usrclass: bool
    ) -> Iterator[tuple[UserProfile, HiveProtocol]]:
        """Yield each user profile paired with one of its opened hives."""
        for user_profile in self._profiles:
            path = user_profile.usrclass_path if usrclass else user_profile.ntuser_path
            if path is None:
                continue
            hive = self.registry.open_hive(path)
            if hive is not None:
                yield user_profile, hive

    def resolve_clsid_default(self, hive: HiveProtocol, subpath: str) -> str:
        """Return the (Default) value at a registry subpath, or empty string."""
        node = self.registry.load_subtree(hive, subpath)
        if node is None:
            return ""
        default_value = node.get("(Default)")
        return str(default_value) if default_value else ""

    def hive_inventory(self) -> tuple[HiveRecord, ...]:
        """Return what became of every hive this scan expected to read."""
        attempts = self.registry.open_attempts()
        records = [
            self._hive_record(attempts, name.upper(), "", path)
            for name, path in sorted(self._hives.items())
        ]
        for user_profile in self._profiles:
            for hive_name, path in (
                ("NTUSER.DAT", user_profile.ntuser_path),
                ("UsrClass.dat", user_profile.usrclass_path),
            ):
                if path is not None:
                    records.append(
                        self._hive_record(
                            attempts, hive_name, user_profile.username, path
                        )
                    )
        if not self._standalone:
            records.extend(self._uncollected_machine_hives())
        return tuple(records)

    @staticmethod
    def _hive_record(
        attempts: dict[str, HiveRecord], name: str, owner: str, path: Path
    ) -> HiveRecord:
        """Name a recorded open attempt, or report a hive nothing asked for."""
        attempt = attempts.get(hive_key(path))
        if attempt is None:
            return HiveRecord(
                name=name, owner=owner, path=str(path), status=HiveStatus.NOT_READ
            )
        return dataclasses.replace(attempt, name=name, owner=owner)

    def _uncollected_machine_hives(self) -> list[HiveRecord]:
        """Report machine hives the image never supplied."""
        return [
            HiveRecord(name=name.upper(), status=HiveStatus.NOT_COLLECTED)
            for name in sorted(_KNOWN_HIVE_NAMES - _USER_HIVE_NAMES)
            if name not in self._hives
        ]

    def resolve_clsid_inproc(self, hive: HiveProtocol, clsid: str) -> str:
        """Look up a CLSID's InprocServer32 DLL in either machine registry view."""
        if not clsid.startswith("{"):
            return ""
        for class_root in _MACHINE_CLASS_ROOTS:
            dll_path = self.resolve_clsid_default(
                hive, f"{class_root}\\CLSID\\{clsid}\\InprocServer32"
            )
            if dll_path:
                return dll_path
        return ""


def build_context(path: Path, *, hostname: str = "") -> AnalysisContext:
    """Build an AnalysisContext from a directory or standalone hive file."""
    # A context is one scan, so the ledger of what that scan lost starts here.
    ledger.reset()
    try:
        resolved = path.resolve()
    except OSError:
        # An image the platform will not resolve is still worth probing by
        # the name the analyst gave; safe_exists decides whether it is there.
        resolved = path
    if not safe_exists(resolved):
        raise FileNotFoundError(f"Scan target does not exist: {path}")

    if classify_input(resolved) is ArtifactKind.HIVE_FILE:
        root, hives, profiles = build_hive_context(resolved)
        standalone = True
    else:
        root = resolved
        hives = discover_hives(root)
        profiles = discover_profiles(root)
        standalone = False

    return AnalysisContext(
        root=root,
        hives=hives,
        user_profiles=profiles,
        registry=RegistryHelper(),
        filesystem=FilesystemHelper(image_root=root),
        hostname_override=hostname,
        standalone=standalone,
    )
