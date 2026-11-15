"""Windows path, command line, and executable classification helpers."""

from __future__ import annotations

import functools
import os
import re
import shlex
from pathlib import Path, PureWindowsPath

from pyrsistencesniper.core.lolbins import load_lolbin_names

__all__ = [
    "BUILTIN_NAMES",
    "ENV_VAR_TABLE",
    "OS_SYSTEM_PATHS",
    "SCRIPT_LAUNCHERS",
    "canonicalize_windows_path",
    "expand_env_vars",
    "extract_executable_from_cmdline",
    "is_builtin",
    "is_in_os_directory",
    "is_lolbin",
    "is_representable_windows_path",
    "normalize_windows_path",
    "read_bounded",
]

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

_EXECUTABLE_EXTS: tuple[str, ...] = (
    ".exe",
    ".dll",
    ".com",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".scr",
    ".msi",
)

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

_POWERSHELL_TARGET_FLAGS: frozenset[str] = frozenset(
    {"-file", "-f", "-command", "-c", "-encodedcommand", "-enc", "-e", "-ec"}
)

_POWERSHELL_VALUE_FLAG_NAMES: frozenset[str] = frozenset(
    {
        "executionpolicy",
        "windowstyle",
        "inputformat",
        "outputformat",
        "version",
        "configurationname",
        "psconsolefile",
    }
)

_POWERSHELL_VALUE_FLAG_ALIASES: frozenset[str] = frozenset({"ep", "of"})

_ENV_PATTERN = re.compile(r"%[^%]+%", re.IGNORECASE)
_DEVICE_PREFIX_RE = re.compile(r"^(?:\\\\[?.]\\|\\[?][?]\\)")
_ARG_PLACEHOLDER_RE = re.compile(r"^%[0-9*lvwd]$", re.IGNORECASE)
_DRIVE_PREFIX_LEN = 2

_LONG_PATH_PREFIX = "\\\\?\\"
_UNC_PREFIX = "\\\\"
_LONG_PATH_UNC_PREFIX = "\\\\?\\UNC\\"

# Win32 caps a path at MAX_PATH (260) and a directory at MAX_PATH minus room for
# an 8.3 name, so 248 is the first length at which any call may start refusing.
_LONG_PATH_LIMIT = 248

# NTFS caps a name component at 255 characters and Win32 caps a whole path at
# 32767 even behind the \\?\ prefix. Those are limits of the image, not of the
# analyst's host, so they are checked as a string: letting a syscall discover
# them instead makes one image read differently on each host, because POSIX
# refuses at its own much smaller PATH_MAX and Win32 does not refuse until far
# past it.
_WINDOWS_PATH_LIMIT = 32767
_WINDOWS_COMPONENT_LIMIT = 255


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


def canonicalize_windows_path(path: str) -> str:
    """Normalize a Windows path into an image-relative form for offline resolution."""
    path_string = path.strip().strip("'\"")
    if not path_string:
        return ""

    path_string = path_string.replace("/", "\\")
    path_string = _DEVICE_PREFIX_RE.sub("", path_string)

    if path_string.startswith("\\\\"):
        return ""

    if len(path_string) >= _DRIVE_PREFIX_LEN and path_string[1] == ":":
        path_string = path_string[2:]

    stripped = path_string.lstrip("\\")
    if stripped.lower().startswith("systemroot\\"):
        path_string = "Windows\\" + stripped.split("\\", 1)[1]

    stripped = path_string.lstrip("\\")
    lower = stripped.lower()
    if lower.startswith(("system32\\", "syswow64\\")):
        path_string = "Windows\\" + stripped

    return path_string.lstrip("\\")


def is_representable_windows_path(path: str) -> bool:
    """Report whether a Windows volume could hold this path at all."""
    # No filename may contain NUL. This is checked here rather than left to the
    # platform because Python 3.14 on Windows stopped raising for an embedded
    # NUL in Path.resolve(), so the caller can no longer learn it from an
    # exception, and the same poisoned value would read differently per host.
    if "\x00" in path:
        return False
    # len() counts code points where NTFS counts UTF-16 units, so this is
    # permissive for astral characters, which is the safe direction: it only
    # ever accepts a name Windows itself would reject.
    if len(path) > _WINDOWS_PATH_LIMIT:
        return False
    return all(
        len(component) <= _WINDOWS_COMPONENT_LIMIT
        for component in path.replace("/", "\\").split("\\")
    )


def _on_windows() -> bool:
    """Report whether this process is running on Windows itself."""
    # The one place the host OS is read. A test reaching the Win32-only branches
    # patches this instead of os.name, which on Python 3.10 and 3.11 also decides
    # what pathlib.Path() builds and makes any bare Path() on POSIX raise.
    return os.name == "nt"


def _io_path(path: Path) -> Path:
    """Return the path to hand a syscall, prefixed where Windows needs it."""
    # With LongPathsEnabled at 0, Win32 reports a path at or over MAX_PATH as
    # "not found", which a scanner cannot tell from an absent file. The prefix
    # lifts the limit but disables normalization, so it is applied only to an
    # absolute path with no relative segment, and only where the result goes
    # straight to the OS. Never use it for a path that is logged or compared
    # against the image root, which is why resolve() does not.
    if not _on_windows():
        return path
    text = str(path)
    if len(text) < _LONG_PATH_LIMIT or text.startswith(_LONG_PATH_PREFIX):
        return path
    if not path.is_absolute() or ".." in path.parts:
        return path
    if text.startswith(_UNC_PREFIX):
        return Path(_LONG_PATH_UNC_PREFIX + text[len(_UNC_PREFIX) :])
    return Path(_LONG_PATH_PREFIX + text)


# Every whole-file read of something the image supplies goes through here. A
# hostile image names its own file sizes, so an uncapped read hands it the
# scanner's memory.
def read_bounded(path: Path, limit: int) -> bytes:
    """Read a whole file, raising ValueError when it is larger than the limit."""
    with _io_path(path).open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"file exceeds {limit} bytes")
    return data


def _extract_cmd_target(parts: list[str]) -> str:
    """Extract the target executable from a cmd invocation."""
    # Every leading switch is skipped so ``cmd /q /c prog`` resolves to the
    # program, and empty tokens are skipped because cmd's doubled-quote form
    # leaves one behind.
    for token in parts[1:]:
        if token.startswith("/"):
            continue
        candidate = token.strip('"')
        if candidate:
            return candidate
    return parts[0].strip('"')


def _extract_rundll_target(parts: list[str]) -> str:
    """Extract the DLL path from a rundll32 invocation."""
    dll_part = parts[1].strip('"')
    comma_idx = dll_part.find(",")
    return dll_part[:comma_idx] if comma_idx != -1 else dll_part


def _is_argument_placeholder(token: str) -> bool:
    """Report whether a token is a shell argument placeholder such as %1 or %*."""
    # Registered handlers read ``wscript.exe "%1"``, the target arriving at
    # invocation time. Treating the placeholder as the target would report an
    # unresolvable value and lose the interpreter.
    return bool(_ARG_PLACEHOLDER_RE.match(token))


def _consumes_next_token(flag: str) -> bool:
    """Report whether a PowerShell flag takes the following token as its value."""
    # PowerShell binds any unambiguous prefix, so ``-exec``, ``-ex`` and
    # ``-win`` are all valid. Matching only full names would let a flag's value
    # be mistaken for the payload.
    name = flag.lstrip("-")
    if not name:
        return False
    if name in _POWERSHELL_VALUE_FLAG_ALIASES:
        return True
    return any(full.startswith(name) for full in _POWERSHELL_VALUE_FLAG_NAMES)


def _extract_powershell_target(parts: list[str]) -> str:
    """Extract the script or command a PowerShell invocation ultimately runs."""
    # A flag that consumes a value (``-ExecutionPolicy Bypass``) is skipped in
    # pairs so the value is not mistaken for the target.
    index = 1
    while index < len(parts):
        token = parts[index]
        lowered = token.lower()
        if not lowered.startswith("-"):
            candidate = token.strip('"')
            if not _is_argument_placeholder(candidate):
                return candidate
            index += 1
            continue
        if lowered in _POWERSHELL_TARGET_FLAGS:
            if index + 1 < len(parts):
                candidate = parts[index + 1].strip('"')
                if not _is_argument_placeholder(candidate):
                    return candidate
            break
        index += 2 if _consumes_next_token(lowered) else 1
    return parts[0].strip('"')


def _extract_script_host_target(parts: list[str]) -> str:
    """Extract the script argument of a wscript, cscript, or mshta invocation."""
    for token in parts[1:]:
        if token.startswith("//"):
            continue
        candidate = token.strip('"')
        if _is_argument_placeholder(candidate):
            continue
        return candidate
    return parts[0].strip('"')


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
        return _extract_script_host_target(parts)
    return None


def _cmdline_parts(cmdline: str) -> list[str]:
    """Split a registry command line into tokens, tolerating unbalanced quotes."""
    stripped = cmdline.strip()
    if not stripped:
        return []
    try:
        return shlex.split(stripped, posix=False)
    except ValueError:
        # Unbalanced quoting is normal in registry command lines; splitting on
        # whitespace is the documented fallback, not a failure to report.
        return stripped.split()


def _leading_executable_name(parts: list[str]) -> str:
    """Return the lowercase filename of the command line's first token."""
    first = parts[0].strip('"').lower().replace("/", "\\")
    return PureWindowsPath(first).name.lower()


def extract_launcher_from_cmdline(cmdline: str) -> str:
    """Return the launcher a command line runs its payload through, else empty."""
    # Reported only when a separate payload was peeled off: a bare LOLBin with
    # no arguments is itself the executable the entry runs, so it is classified
    # directly rather than described as its own launcher.
    parts = _cmdline_parts(cmdline)
    if len(parts) <= 1:
        return ""
    launcher_name = _leading_executable_name(parts)
    if launcher_name.removesuffix(".exe") not in SCRIPT_LAUNCHERS:
        return ""
    if _extract_launcher_target(launcher_name, parts) is None:
        return ""
    return launcher_name


def extract_executable_from_cmdline(cmdline: str) -> str:
    """Extract the executable path from a command line."""
    stripped = cmdline.strip()
    parts = _cmdline_parts(cmdline)
    if not parts:
        return ""

    first_name = _leading_executable_name(parts)

    if first_name.removesuffix(".exe") in SCRIPT_LAUNCHERS:
        result = _extract_launcher_target(first_name, parts)
        if result is not None:
            return result

    # CreateProcess semantics: an unquoted path with spaces runs to the first
    # token ending in an executable extension, not to the first space.
    if not stripped.startswith('"') and "\\" in parts[0]:
        joined = parts[0]
        for part in parts[1:]:
            if joined.lower().endswith(_EXECUTABLE_EXTS):
                break
            joined = f"{joined} {part}"
        if joined.lower().endswith(_EXECUTABLE_EXTS):
            return joined

    return parts[0].strip('"')


def _executable_name(path: str) -> str:
    """Extract the lowercase filename component from a Windows path."""
    return PureWindowsPath(path).name.lower()


@functools.cache
def _lolbin_names() -> frozenset[str]:
    """Return the LOLBin filenames, plus the shells LOLBAS deliberately omits."""
    # LOLBAS lists neither powershell.exe nor pwsh.exe: a shell is not a binary
    # repurposed for something it was not built for. For persistence triage an
    # entry running its payload through PowerShell is as notable as one running
    # it through mshta, so the launchers are folded back in.
    return load_lolbin_names() | {f"{name}.exe" for name in SCRIPT_LAUNCHERS}


def is_lolbin(path: str) -> bool:
    """Report whether the filename is a known Living Off The Land Binary."""
    return _executable_name(path) in _lolbin_names()


def is_builtin(path: str) -> bool:
    """Report whether the filename is a known Windows built-in process."""
    return _executable_name(path) in BUILTIN_NAMES


def is_in_os_directory(path: str) -> bool:
    """Report whether the path resides under a known OS system directory."""
    canonical = canonicalize_windows_path(path).lower()
    return any(canonical.startswith(prefix + "\\") for prefix in OS_SYSTEM_PATHS)
