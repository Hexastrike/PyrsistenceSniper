"""Windows path and registry path normalization for offline resolution."""

from __future__ import annotations

import re
import shlex
from pathlib import PureWindowsPath

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

_ENV_PATTERN = re.compile(r"%[^%]+%", re.IGNORECASE)

_LAUNCHER_PREFIXES: tuple[str, ...] = (
    "rundll32",
    "rundll32.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "cmd",
    "cmd.exe",
    "mshta",
    "mshta.exe",
    "wscript",
    "wscript.exe",
    "cscript",
    "cscript.exe",
)

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
    if first_name in ("cmd", "cmd.exe") and len(parts) > 1:
        return _extract_cmd_target(parts)
    if first_name in ("rundll32", "rundll32.exe") and len(parts) > 1:
        return _extract_rundll_target(parts)
    if first_name in (
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
    ):
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

    if first_name in _LAUNCHER_PREFIXES:
        result = _extract_launcher_target(first_name, parts)
        if result is not None:
            return result

    return parts[0].strip('"')


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
