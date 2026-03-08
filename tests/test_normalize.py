from __future__ import annotations

from pyrsistencesniper.resolution.normalize import (
    canonicalize_registry_path,
    canonicalize_windows_path,
    expand_env_vars,
    extract_executable_from_cmdline,
    normalize_windows_path,
)

# -- expand_env_vars ----------------------------------------------------------


def test_expand_windir() -> None:
    result = expand_env_vars("%windir%\\system32\\cmd.exe")
    assert result == "Windows\\system32\\cmd.exe"


def test_expand_systemroot() -> None:
    assert expand_env_vars("%SystemRoot%\\notepad.exe") == "Windows\\notepad.exe"


def test_expand_programfiles() -> None:
    result = expand_env_vars("%ProgramFiles%\\app\\app.exe")
    assert result == "Program Files\\app\\app.exe"


def test_expand_userprofile_with_username() -> None:
    result = expand_env_vars("%USERPROFILE%\\Desktop", username="Alice")
    assert result == "Users\\Alice\\Desktop"


def test_expand_userprofile_default_when_no_username() -> None:
    result = expand_env_vars("%USERPROFILE%\\Desktop")
    assert result == "Users\\DEFAULT\\Desktop"


def test_expand_unknown_var_left_as_is() -> None:
    result = expand_env_vars("%UNKNOWN_VAR%\\foo")
    assert result == "%UNKNOWN_VAR%\\foo"


def test_expand_multiple_vars() -> None:
    result = expand_env_vars("%windir%\\%windir%")
    assert result == "Windows\\Windows"


# -- extract_executable_from_cmdline ------------------------------------------


def test_extract_simple_exe() -> None:
    assert extract_executable_from_cmdline("notepad.exe") == "notepad.exe"


def test_extract_path_with_args() -> None:
    result = extract_executable_from_cmdline("C:\\app.exe --verbose")
    assert result == "C:\\app.exe"


def test_extract_empty() -> None:
    assert extract_executable_from_cmdline("") == ""


def test_extract_cmd_c() -> None:
    result = extract_executable_from_cmdline("cmd.exe /c script.bat")
    assert result == "script.bat"


def test_extract_rundll32() -> None:
    result = extract_executable_from_cmdline("rundll32.exe shell32.dll,Control_RunDLL")
    assert result == "shell32.dll"


def test_extract_powershell_script() -> None:
    cmdline = "powershell.exe -ExecutionPolicy Bypass script.ps1"
    result = extract_executable_from_cmdline(cmdline)
    assert result == "Bypass"


def test_extract_powershell_file_flag() -> None:
    result = extract_executable_from_cmdline("powershell.exe -File script.ps1")
    assert result == "script.ps1"


def test_extract_mshta() -> None:
    result = extract_executable_from_cmdline("mshta.exe vbscript:Execute(code)")
    assert result == "vbscript:Execute(code)"


# -- normalize_windows_path ---------------------------------------------------


def test_normalize_forward_slashes() -> None:
    assert normalize_windows_path("C:/Windows/System32") == "C:\\Windows\\System32"


def test_normalize_mixed_slashes() -> None:
    result = normalize_windows_path("C:\\Windows/System32\\cmd.exe")
    assert result == "C:\\Windows\\System32\\cmd.exe"


def test_normalize_preserves_clean_path() -> None:
    assert normalize_windows_path("C:\\Windows\\System32") == "C:\\Windows\\System32"


# -- canonicalize_registry_path -----------------------------------------------


def test_canonicalize_hkey_local_machine() -> None:
    result = canonicalize_registry_path("HKEY_LOCAL_MACHINE\\Software\\Run")
    assert result == "HKLM\\Software\\Run"


def test_canonicalize_hklm_passthrough() -> None:
    assert canonicalize_registry_path("HKLM\\Software\\Run") == "HKLM\\Software\\Run"


def test_canonicalize_hkey_current_user() -> None:
    result = canonicalize_registry_path("HKEY_CURRENT_USER\\Software")
    assert result == "HKCU\\Software"


def test_canonicalize_hkey_users() -> None:
    result = canonicalize_registry_path("HKEY_USERS\\S-1-5-21\\Software")
    assert result == "HKU\\S-1-5-21\\Software"


def test_canonicalize_strips_leading_slash() -> None:
    result = canonicalize_registry_path("\\HKLM\\Software\\")
    assert result == "HKLM\\Software"


def test_canonicalize_forward_slashes() -> None:
    result = canonicalize_registry_path("HKEY_LOCAL_MACHINE/Software/Run")
    assert result == "HKLM\\Software\\Run"


# -- canonicalize_windows_path ------------------------------------------------


def test_canonicalize_windows_path_drive_c() -> None:
    assert canonicalize_windows_path("C:\\Windows\\System32") == "Windows\\System32"


def test_canonicalize_windows_path_drive_d() -> None:
    assert canonicalize_windows_path("D:\\Tools\\app.exe") == "Tools\\app.exe"


def test_canonicalize_windows_path_forward_slash() -> None:
    assert canonicalize_windows_path("C:/Windows/System32") == "Windows\\System32"


def test_canonicalize_windows_path_mixed_slash() -> None:
    result = canonicalize_windows_path("C:\\Windows/System32\\cmd.exe")
    assert result == "Windows\\System32\\cmd.exe"


def test_canonicalize_windows_path_no_drive() -> None:
    result = canonicalize_windows_path("Windows\\System32\\cmd.exe")
    assert result == "Windows\\System32\\cmd.exe"


def test_canonicalize_windows_path_leading_backslash() -> None:
    assert canonicalize_windows_path("\\Windows\\System32") == "Windows\\System32"


def test_canonicalize_windows_path_double_quotes() -> None:
    assert canonicalize_windows_path('"C:\\Windows\\System32"') == "Windows\\System32"


def test_canonicalize_windows_path_single_quotes() -> None:
    assert canonicalize_windows_path("'C:\\Windows\\System32'") == "Windows\\System32"


def test_canonicalize_windows_path_device_unc_question() -> None:
    result = canonicalize_windows_path("\\\\?\\C:\\Windows\\System32")
    assert result == "Windows\\System32"


def test_canonicalize_windows_path_device_dos() -> None:
    result = canonicalize_windows_path("\\??\\C:\\Windows\\System32")
    assert result == "Windows\\System32"


def test_canonicalize_windows_path_device_dot() -> None:
    result = canonicalize_windows_path("\\\\.\\C:\\Windows\\System32")
    assert result == "Windows\\System32"


def test_canonicalize_windows_path_unc_named() -> None:
    assert canonicalize_windows_path("\\\\server\\share\\file.txt") == ""


def test_canonicalize_windows_path_unc_ip() -> None:
    assert canonicalize_windows_path("\\\\192.168.1.1\\c$\\Windows") == ""


def test_canonicalize_windows_path_empty() -> None:
    assert canonicalize_windows_path("") == ""


def test_canonicalize_windows_path_whitespace() -> None:
    assert canonicalize_windows_path("   ") == ""


def test_canonicalize_windows_path_bare_filename() -> None:
    assert canonicalize_windows_path("cmd.exe") == "cmd.exe"


def test_canonicalize_windows_path_systemroot_prefix() -> None:
    result = canonicalize_windows_path("\\SystemRoot\\System32\\drivers\\srv.sys")
    assert result == "Windows\\System32\\drivers\\srv.sys"


def test_canonicalize_windows_path_systemroot_case_insensitive() -> None:
    result = canonicalize_windows_path("\\SYSTEMROOT\\System32\\cmd.exe")
    assert result == "Windows\\System32\\cmd.exe"


def test_canonicalize_windows_path_bare_system32() -> None:
    result = canonicalize_windows_path("System32\\svchost.exe")
    assert result == "Windows\\System32\\svchost.exe"


def test_canonicalize_windows_path_bare_syswow64() -> None:
    result = canonicalize_windows_path("SysWOW64\\ntdll.dll")
    assert result == "Windows\\SysWOW64\\ntdll.dll"


def test_canonicalize_windows_path_system32_with_leading_backslash() -> None:
    result = canonicalize_windows_path("\\System32\\svchost.exe")
    assert result == "Windows\\System32\\svchost.exe"


# -- extract_executable_from_cmdline (additional cases) -----------------------


def test_extract_executable_wscript() -> None:
    result = extract_executable_from_cmdline("wscript.exe C:\\scripts\\evil.vbs")
    assert result == "C:\\scripts\\evil.vbs"


def test_extract_executable_cscript() -> None:
    result = extract_executable_from_cmdline("cscript.exe //nologo script.js")
    assert result == "//nologo"


def test_extract_executable_rundll32_full_path() -> None:
    result = extract_executable_from_cmdline(
        "C:\\Windows\\System32\\rundll32.exe advpack.dll,LaunchINFSection"
    )
    assert result == "advpack.dll"


def test_extract_executable_cmd_k() -> None:
    assert extract_executable_from_cmdline("cmd.exe /k netstat.exe") == "netstat.exe"


def test_extract_executable_quoted_exe() -> None:
    result = extract_executable_from_cmdline('"C:\\Program Files\\app.exe" --flag')
    assert result == "C:\\Program"


def test_extract_executable_powershell_only_flags() -> None:
    result = extract_executable_from_cmdline(
        "powershell.exe -NoProfile -NonInteractive"
    )
    assert result == "powershell.exe"
