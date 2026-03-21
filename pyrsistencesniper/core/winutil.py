"""Windows path normalization, command-line extraction, and classification."""

from __future__ import annotations

import logging
import re
import shlex
from pathlib import PureWindowsPath

from pyrsistencesniper.core.lolbins import load_lolbin_names

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ENV_VAR_TABLE: dict[str, str] = {
    "%systemroot%": "Windows",
    "%windir%": "Windows",
    "%programfiles%": "Program Files",
    "%programfiles(x86)%": "Program Files (x86)",
    "%programdata%": "ProgramData",
    "%commonprogramfiles%": "Program Files\\Common Files",
    "%commonprogramfiles(x86)%": "Program Files (x86)\\Common Files",
    "%systemdrive%": "C:",
    "%homedrive%": "C:",
    "%allusersprofile%": "ProgramData",
    "%public%": "Users\\Public",
    "%temp%": "Users\\{username}\\AppData\\Local\\Temp",
    "%tmp%": "Users\\{username}\\AppData\\Local\\Temp",
    "%appdata%": "Users\\{username}\\AppData\\Roaming",
    "%localappdata%": "Users\\{username}\\AppData\\Local",
    "%userprofile%": "Users\\{username}",
    "%homepath%": "Users\\{username}",
}

_REGISTRY_ROOTS: dict[str, str] = {
    "hkey_local_machine": "HKLM",
    "hklm": "HKLM",
    "hkey_users": "HKU",
    "hku": "HKU",
    "hkey_current_user": "HKCU",
    "hkcu": "HKCU",
    "hkey_classes_root": "HKCR",
    "hkcr": "HKCR",
    "hkey_current_config": "HKCC",
    "hkcc": "HKCC",
}

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

SCRIPT_LAUNCHERS: frozenset[str] = frozenset(
    {
        "cmd",
        "powershell",
        "pwsh",
        "mshta",
        "wscript",
        "cscript",
        "rundll32",
    }
)

# ---------------------------------------------------------------------------
# Path functions
# ---------------------------------------------------------------------------

_ENV_PATTERN = re.compile(r"%[^%]+%", re.IGNORECASE)


def expand_env_vars(value: str, username: str = "") -> str:
    """Expand Windows environment variables using a static lookup table."""

    def _replace(match: re.Match[str]) -> str:
        var = match.group(0).lower()
        replacement = ENV_VAR_TABLE.get(var)
        if replacement is None:
            return match.group(0)
        if "{username}" in replacement:
            return replacement.replace("{username}", username or "DEFAULT")
        return replacement

    return _ENV_PATTERN.sub(_replace, value)


def normalize_windows_path(path: str) -> str:
    """Normalize path separators to backslashes using PureWindowsPath."""
    return str(PureWindowsPath(path))


_DEVICE_PREFIX_RE = re.compile(r"^(?:\\\\[?.]\\|\\[?][?]\\)")


def canonicalize_windows_path(path: str) -> str:
    """Normalize a Windows path for offline resolution."""
    path_string = path.strip().strip("'\"")
    if not path_string:
        return ""

    path_string = path_string.replace("/", "\\")
    path_string = _DEVICE_PREFIX_RE.sub("", path_string)

    if path_string.startswith("\\\\"):
        return ""

    _drive_prefix_len = 2
    if len(path_string) >= _drive_prefix_len and path_string[1] == ":":
        path_string = path_string[2:]

    # Translate \SystemRoot\ to Windows\
    stripped = path_string.lstrip("\\")
    if stripped.lower().startswith("systemroot\\"):
        path_string = "Windows\\" + stripped.split("\\", 1)[1]

    # Prefix bare System32\ or SysWOW64\ with Windows\
    stripped = path_string.lstrip("\\")
    lower = stripped.lower()
    if lower.startswith("system32\\") or lower.startswith("syswow64\\"):
        path_string = "Windows\\" + stripped

    return path_string.lstrip("\\")


def canonicalize_registry_path(path: str) -> str:
    """Normalize a registry path, converting long-form root names to short form."""
    normalized = path.replace("/", "\\").strip("\\")
    parts = normalized.split("\\", 1)
    if not parts:
        return normalized
    root_lower = parts[0].lower()
    canonical_root = _REGISTRY_ROOTS.get(root_lower)
    if canonical_root:
        if len(parts) > 1:
            return f"{canonical_root}\\{parts[1]}"
        return canonical_root
    return normalized


# ---------------------------------------------------------------------------
# Command-line extraction
# ---------------------------------------------------------------------------

_MIN_PARTS_FOR_ARG = 2


def _extract_cmd_target(parts: list[str]) -> str:
    """Extract the target executable from a cmd /c or /k invocation."""
    if len(parts) <= 1:
        return parts[0].strip('"') if parts else ""
    flag = parts[1].lower()
    if flag in ("/c", "/k") and len(parts) > _MIN_PARTS_FOR_ARG:
        return parts[_MIN_PARTS_FOR_ARG].strip('"')
    return parts[1].strip('"')


def _extract_rundll_target(parts: list[str]) -> str:
    """Extract the DLL path from a rundll32 invocation."""
    dll_part = parts[1].strip('"')
    comma_idx = dll_part.find(",")
    return dll_part[:comma_idx] if comma_idx != -1 else dll_part


def _extract_powershell_target(parts: list[str]) -> str:
    """Extract the first non-flag argument from a PowerShell invocation."""
    for part in parts[1:]:
        if not part.lower().startswith("-"):
            return part.strip('"')
    return parts[0]


def _extract_launcher_target(first_name: str, parts: list[str]) -> str | None:
    """Resolve the real executable behind a launcher prefix, or None."""
    bare = first_name.removesuffix(".exe")
    if bare == "cmd" and len(parts) > 1:
        return _extract_cmd_target(parts)
    if bare == "rundll32" and len(parts) > 1:
        return _extract_rundll_target(parts)
    if bare in ("powershell", "pwsh"):
        return _extract_powershell_target(parts)
    if len(parts) > 1:
        return parts[1].strip('"')
    return None


def extract_executable_from_cmdline(cmdline: str) -> str:
    """Extract the executable path from a command line."""
    stripped = cmdline.strip().strip('"')
    if not stripped:
        return ""

    try:
        parts = shlex.split(stripped, posix=False)
    except ValueError:
        parts = stripped.split()

    if not parts:
        return ""

    first = parts[0].lower().replace("/", "\\")
    first_name = PureWindowsPath(first).name.lower()

    if first_name.removesuffix(".exe") in SCRIPT_LAUNCHERS:
        result = _extract_launcher_target(first_name, parts)
        if result is not None:
            return result

    return parts[0].strip('"')


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

_lolbin_cache: dict[str, frozenset[str]] = {}


def _executable_name(path: str) -> str:
    """Extract the lowercase filename component from a Windows path."""
    return PureWindowsPath(path).name.lower()


def _get_lolbin_names() -> frozenset[str]:
    """Return the lazily-loaded set of LOLBin filenames."""
    if "names" not in _lolbin_cache:
        _lolbin_cache["names"] = load_lolbin_names()
    return _lolbin_cache["names"]


def is_lolbin(path: str) -> bool:
    """Return True if the filename is a known Living Off The Land Binary."""
    return _executable_name(path) in _get_lolbin_names()


def is_builtin(path: str) -> bool:
    """Return True if the filename is a known Windows built-in process."""
    return _executable_name(path) in BUILTIN_NAMES


def is_in_os_directory(path: str) -> bool:
    """Return True if the path resides under a known OS system directory."""
    canonical = canonicalize_windows_path(path).lower()
    return any(canonical.startswith(prefix + "\\") for prefix in OS_SYSTEM_PATHS)
