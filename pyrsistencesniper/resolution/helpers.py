from __future__ import annotations

from pathlib import PureWindowsPath

from pyrsistencesniper.resolution.lolbins import load_lolbin_names
from pyrsistencesniper.resolution.normalize import canonicalize_windows_path

_lolbin_names: frozenset[str] | None = None


def _executable_name(path: str) -> str:
    """Extract the lowercase filename component from a Windows path."""
    return PureWindowsPath(path).name.lower()


def _get_lolbin_names() -> frozenset[str]:
    """Return the lazily-loaded set of LOLBin filenames."""
    global _lolbin_names
    if _lolbin_names is None:
        _lolbin_names = load_lolbin_names()
    return _lolbin_names


BUILTIN_NAMES: frozenset[str] = frozenset(
    {
        "explorer.exe",
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "spoolsv.exe",
        "taskhostw.exe",
        "sihost.exe",
        "ctfmon.exe",
        "conhost.exe",
        "dwm.exe",
        "fontdrvhost.exe",
        "dllhost.exe",
        "searchindexer.exe",
        "searchprotocolhost.exe",
        "searchfilterhost.exe",
        "runtimebroker.exe",
        "securityhealthservice.exe",
        "securityhealthsystray.exe",
        "sgrmbroker.exe",
        "smartscreen.exe",
    }
)

OS_SYSTEM_PATHS: frozenset[str] = frozenset(
    {
        "windows\\system32",
        "windows\\syswow64",
    }
)


def is_lolbin(path: str) -> bool:
    """Return True if the filename is a known Living Off The Land Binary."""
    return _executable_name(path) in _get_lolbin_names()


def is_builtin(path: str) -> bool:
    """Return True if the filename is a known Windows built-in process."""
    return _executable_name(path) in BUILTIN_NAMES


def _in_system_path(path: str) -> bool:
    """Return True if the path resides under a known OS system directory."""
    canonical = canonicalize_windows_path(path).lower()
    if "\\" not in canonical:
        return False
    parent = canonical.rsplit("\\", 1)[0]
    while parent:
        if parent in OS_SYSTEM_PATHS:
            return True
        if "\\" not in parent:
            break
        parent = parent.rsplit("\\", 1)[0]
    return parent in OS_SYSTEM_PATHS
