from __future__ import annotations

from pyrsistencesniper.core.helpers import (
    _in_system_path,
    is_builtin,
    is_lolbin,
    is_os_executable,
    is_os_library,
)

# -- is_lolbin ----------------------------------------------------------------


def test_is_lolbin_mshta() -> None:
    assert is_lolbin("C:\\Windows\\System32\\mshta.exe") is True


def test_is_lolbin_certutil() -> None:
    assert is_lolbin("C:\\Windows\\System32\\certutil.exe") is True


def test_is_lolbin_notepad_is_not() -> None:
    assert is_lolbin("C:\\Windows\\System32\\notepad.exe") is False


def test_is_lolbin_case_insensitive() -> None:
    assert is_lolbin("C:\\Windows\\System32\\MSHTA.EXE") is True


# -- is_builtin ---------------------------------------------------------------


def test_is_builtin_explorer() -> None:
    assert is_builtin("C:\\Windows\\explorer.exe") is True


def test_is_builtin_svchost() -> None:
    assert is_builtin("C:\\Windows\\System32\\svchost.exe") is True


def test_is_builtin_random_exe() -> None:
    assert is_builtin("C:\\Tools\\malware.exe") is False


def test_is_builtin_case_insensitive() -> None:
    assert is_builtin("Explorer.EXE") is True


# -- is_os_executable ---------------------------------------------------------


def test_is_os_executable_svchost_in_system32() -> None:
    assert is_os_executable("C:\\Windows\\System32\\svchost.exe") is True


def test_is_os_executable_not_in_system_path() -> None:
    assert is_os_executable("C:\\Users\\Public\\svchost.exe") is False


def test_is_os_executable_lolbin_excluded() -> None:
    assert is_os_executable("C:\\Windows\\System32\\mshta.exe") is False


# -- is_os_library ------------------------------------------------------------


def test_is_os_library_system32_dll() -> None:
    assert is_os_library("C:\\Windows\\System32\\kernel32.dll") is True


def test_is_os_library_syswow64_dll() -> None:
    assert is_os_library("C:\\Windows\\SysWOW64\\ntdll.dll") is True


def test_is_os_library_exe_is_not_library() -> None:
    assert is_os_library("C:\\Windows\\System32\\cmd.exe") is False


def test_is_os_library_dll_outside_system() -> None:
    assert is_os_library("C:\\Users\\Public\\evil.dll") is False


# -- is_os_executable parent path variants ------------------------------------


def test_is_os_executable_system32_real() -> None:
    assert is_os_executable("C:\\Windows\\System32\\svchost.exe") is True


def test_is_os_executable_syswow64_real() -> None:
    assert is_os_executable("C:\\Windows\\SysWOW64\\svchost.exe") is True


def test_is_os_executable_fake_system32() -> None:
    assert is_os_executable("C:\\fake\\windows\\system32\\svchost.exe") is False


def test_is_os_executable_fake_windows() -> None:
    assert is_os_executable("C:\\attacker\\windows\\svchost.exe") is False


def test_is_os_executable_device_prefix() -> None:
    assert is_os_executable("\\\\?\\C:\\Windows\\System32\\svchost.exe") is True


# -- is_os_library parent path variants ---------------------------------------


def test_is_os_library_system32_real() -> None:
    assert is_os_library("C:\\Windows\\System32\\kernel32.dll") is True


def test_is_os_library_fake_system32() -> None:
    assert is_os_library("C:\\fake\\windows\\system32\\kernel32.dll") is False


def test_is_os_library_device_prefix() -> None:
    assert is_os_library("\\\\?\\C:\\Windows\\System32\\kernel32.dll") is True


# -- _in_system_path ancestor walk -------------------------------------------


def test_in_system_path_direct_child() -> None:
    assert _in_system_path("C:\\Windows\\System32\\svchost.exe") is True


def test_in_system_path_subdirectory() -> None:
    assert _in_system_path("C:\\Windows\\System32\\drivers\\srv.sys") is True


def test_in_system_path_deep_subdirectory() -> None:
    assert _in_system_path("C:\\Windows\\System32\\wbem\\wmiprvse.exe") is True


def test_in_system_path_windows_temp_not_matched() -> None:
    assert _in_system_path("C:\\Windows\\Temp\\evil.exe") is False


def test_in_system_path_program_files_not_matched() -> None:
    assert _in_system_path("C:\\Program Files\\Vendor\\app.exe") is False


def test_in_system_path_user_path_not_matched() -> None:
    assert _in_system_path("C:\\Users\\test\\malware.exe") is False


def test_in_system_path_systemroot_prefix() -> None:
    assert _in_system_path("\\SystemRoot\\System32\\drivers\\srv.sys") is True


def test_in_system_path_bare_system32() -> None:
    assert _in_system_path("System32\\svchost.exe") is True
