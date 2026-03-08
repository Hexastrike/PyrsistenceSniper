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
        if first_name in ("cmd", "cmd.exe") and len(parts) > 1:
            flag = parts[1].lower()
            if flag in ("/c", "/k") and len(parts) > 2:
                return parts[2].strip('"')
            if len(parts) > 1:
                return parts[1].strip('"')
        if first_name in ("rundll32", "rundll32.exe") and len(parts) > 1:
            dll_part = parts[1].strip('"')
            comma_idx = dll_part.find(",")
            if comma_idx != -1:
                return dll_part[:comma_idx]
            return dll_part
        if first_name in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
            for _i, part in enumerate(parts[1:], start=1):
                low = part.lower()
                if low.startswith("-"):
                    continue
                return part.strip('"')
            return parts[0]
        if len(parts) > 1:
            return parts[1].strip('"')

    return parts[0].strip('"')


def normalize_windows_path(path: str) -> str:
    """Normalize path separators to backslashes using PureWindowsPath."""
    return str(PureWindowsPath(path))


_DEVICE_PREFIX_RE = re.compile(r"^(?:\\\\[?.]\\|\\[?][?]\\)")


def canonicalize_windows_path(path: str) -> str:
    """Normalize a Windows path for offline resolution."""
    p = path.strip().strip("'\"")
    if not p:
        return ""

    p = p.replace("/", "\\")
    p = _DEVICE_PREFIX_RE.sub("", p)

    if p.startswith("\\\\"):
        return ""

    if len(p) >= 2 and p[1] == ":":
        p = p[2:]

    # Translate \SystemRoot\ to Windows\
    stripped = p.lstrip("\\")
    if stripped.lower().startswith("systemroot\\"):
        p = "Windows\\" + stripped.split("\\", 1)[1]

    # Prefix bare System32\ or SysWOW64\ with Windows\
    stripped = p.lstrip("\\")
    lower = stripped.lower()
    if lower.startswith("system32\\") or lower.startswith("syswow64\\"):
        p = "Windows\\" + stripped

    p = p.lstrip("\\")

    return p


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
