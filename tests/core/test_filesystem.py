from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from pyrsistencesniper.core.filesystem import FilesystemHelper

if TYPE_CHECKING:
    from pathlib import Path

# -- resolve ------------------------------------------------------------------


def test_resolve_strips_drive_letter(tmp_path: Path) -> None:
    fs = FilesystemHelper(tmp_path)
    resolved = fs.resolve("C:\\Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_no_drive_letter(tmp_path: Path) -> None:
    fs = FilesystemHelper(tmp_path)
    resolved = fs.resolve("Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


# -- exists -------------------------------------------------------------------


def test_exists_real_file(tmp_path: Path) -> None:
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SOFTWARE").write_bytes(b"\x00" * 16)
    fs = FilesystemHelper(tmp_path)
    assert fs.exists("C:\\Windows\\System32\\config\\SOFTWARE") is True


def test_exists_nonexistent(tmp_path: Path) -> None:
    fs = FilesystemHelper(tmp_path)
    assert fs.exists("C:\\Windows\\System32\\nonexistent.exe") is False


def test_exists_directory_is_not_file(tmp_path: Path) -> None:
    (tmp_path / "Windows" / "System32" / "config").mkdir(parents=True)
    fs = FilesystemHelper(tmp_path)
    assert fs.exists("C:\\Windows\\System32\\config") is False


# -- sha256 -------------------------------------------------------------------


def test_sha256_known_content(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello")
    fs = FilesystemHelper(tmp_path)
    digest = fs.sha256("C:\\sample.bin")
    assert digest == hashlib.sha256(b"hello").hexdigest()


def test_sha256_nonexistent_returns_empty(tmp_path: Path) -> None:
    fs = FilesystemHelper(tmp_path)
    assert fs.sha256("C:\\does_not_exist.txt") == ""


# -- resolve edge cases -------------------------------------------------------


def test_resolve_device_unc(tmp_path: Path) -> None:
    fs = FilesystemHelper(tmp_path)
    resolved = fs.resolve("\\\\?\\C:\\Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_device_dos(tmp_path: Path) -> None:
    fs = FilesystemHelper(tmp_path)
    resolved = fs.resolve("\\??\\C:\\Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_forward_slash(tmp_path: Path) -> None:
    fs = FilesystemHelper(tmp_path)
    resolved = fs.resolve("C:/Windows/System32/config/SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_leading_backslash(tmp_path: Path) -> None:
    fs = FilesystemHelper(tmp_path)
    resolved = fs.resolve("\\Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_unc_returns_root(tmp_path: Path) -> None:
    fs = FilesystemHelper(tmp_path)
    resolved = fs.resolve("\\\\server\\share\\file.txt")
    expected = tmp_path
    assert resolved == expected
