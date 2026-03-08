from __future__ import annotations

from pyrsistencesniper.resolution.helpers import _in_system_path, is_builtin, is_lolbin

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
