"""Tests for FilesystemHelper path resolution, hashing, and safe_iterdir."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PureWindowsPath
from unittest.mock import patch

import pytest
from pyrsistencesniper.core.filesystem import (
    FilesystemHelper,
    safe_iterdir,
)
from pyrsistencesniper.core.windows import _LONG_PATH_LIMIT, io_path, read_bounded


def test_resolve_strips_drive_letter(tmp_path: Path) -> None:
    """The image root replaces C:, since drive letters are meaningless offline."""
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("C:\\Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_no_drive_letter(tmp_path: Path) -> None:
    """Registry values often omit the drive, and must land in the same place."""
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_exists_real_file(tmp_path: Path) -> None:
    """A hive captured by the collection is visible through a Windows-style path."""
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SOFTWARE").write_bytes(b"\x00" * 16)
    filesystem = FilesystemHelper(tmp_path)
    assert filesystem.exists("C:\\Windows\\System32\\config\\SOFTWARE") is True


def test_exists_nonexistent(tmp_path: Path) -> None:
    """An uncollected path is a plain absence, not an error the scan has to handle."""
    filesystem = FilesystemHelper(tmp_path)
    assert filesystem.exists("C:\\Windows\\System32\\nonexistent.exe") is False


def test_exists_directory_is_not_file(tmp_path: Path) -> None:
    """A directory is not something a persistence entry can execute."""
    (tmp_path / "Windows" / "System32" / "config").mkdir(parents=True)
    filesystem = FilesystemHelper(tmp_path)
    assert filesystem.exists("C:\\Windows\\System32\\config") is False


def test_sha256_known_content(tmp_path: Path) -> None:
    """Digests match plain hashlib, so they are comparable against public sources."""
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello")
    filesystem = FilesystemHelper(tmp_path)
    digest = filesystem.sha256("C:\\sample.bin")
    assert digest == hashlib.sha256(b"hello").hexdigest()


def test_sha256_nonexistent_returns_empty(tmp_path: Path) -> None:
    """An uncollected file yields no hash rather than aborting the whole check."""
    filesystem = FilesystemHelper(tmp_path)
    assert filesystem.sha256("C:\\does_not_exist.txt") == ""


def test_resolve_device_unc(tmp_path: Path) -> None:
    """The device-prefixed long-path form is common in ImagePath and must resolve."""
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("\\\\?\\C:\\Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_device_dos(tmp_path: Path) -> None:
    """The NT object-manager prefix used by driver entries resolves the same way."""
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("\\??\\C:\\Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_forward_slash(tmp_path: Path) -> None:
    """Forward slashes from installers name the same file as backslashes do."""
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("C:/Windows/System32/config/SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_leading_backslash(tmp_path: Path) -> None:
    """A root-relative value still lands under the image root, not the host root."""
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("\\Windows\\System32\\config\\SOFTWARE")
    expected = tmp_path / "Windows" / "System32" / "config" / "SOFTWARE"
    assert resolved == expected


def test_resolve_unc_returns_root(tmp_path: Path) -> None:
    """A network share is never part of the image, so there is nothing to resolve."""
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("\\\\server\\share\\file.txt")
    expected = tmp_path
    assert resolved == expected


def test_resolve_parent_traversal_returns_root(tmp_path: Path) -> None:
    """`..` sequences escaping the root are rejected."""
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("..\\..\\..\\etc\\passwd")
    assert resolved == tmp_path.resolve()


def test_resolve_embedded_traversal_returns_root(tmp_path: Path) -> None:
    """Embedded `..` is normalized and rejected if it escapes the root."""
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("Windows\\..\\..\\..\\etc\\passwd")
    assert resolved == tmp_path.resolve()


def test_resolve_symlink_escape_returns_root(tmp_path: Path) -> None:
    """A symlink pointing outside the root is detected and rejected."""
    outside = tmp_path.parent / "outside_target"
    outside.mkdir()
    (outside / "secret.txt").write_text("leak")
    link = tmp_path / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform")
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("escape\\secret.txt")
    assert resolved == tmp_path.resolve()


def test_resolve_traversal_to_valid_child(tmp_path: Path) -> None:
    """Normalized `..` that stays inside root is allowed."""
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "target.txt").write_text("ok")
    filesystem = FilesystemHelper(tmp_path)
    resolved = filesystem.resolve("a\\b\\..\\target.txt")
    assert resolved == (tmp_path / "a" / "target.txt").resolve()


def test_image_relative_names_a_collected_file_by_its_windows_path(
    tmp_path: Path,
) -> None:
    """A file under the root is reported by the path it holds inside the image."""
    filesystem = FilesystemHelper(tmp_path)
    entry = tmp_path / "Users" / "victim" / "Startup" / "evil.lnk"
    assert filesystem.image_relative(entry) == r"Users\victim\Startup\evil.lnk"


def test_image_relative_keeps_a_path_the_image_root_does_not_contain(
    tmp_path: Path,
) -> None:
    """A path outside the image root is reported whole rather than dropped."""
    filesystem = FilesystemHelper(tmp_path / "image")
    outsider = tmp_path / "elsewhere" / "evil.lnk"
    assert filesystem.image_relative(outsider) == str(outsider)


def test_safe_iterdir_returns_entries(tmp_path: Path) -> None:
    """Entries come back under the caller's path, with no long-path prefix leaked."""
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    entries = safe_iterdir(tmp_path)
    assert sorted(entry.name for entry in entries) == ["a.txt", "b.txt"]


def test_safe_iterdir_oserror_returns_empty(tmp_path: Path) -> None:
    """An unreadable directory ends that branch of the walk, not the scan."""
    with patch.object(Path, "iterdir", side_effect=OSError("generic OS error")):
        assert safe_iterdir(tmp_path) == []


def test_safe_iterdir_filenotfounderror_returns_empty(tmp_path: Path) -> None:
    """A directory removed between listing and reading is an absence, not a failure."""
    with patch.object(Path, "iterdir", side_effect=FileNotFoundError("[WinError 3]")):
        assert safe_iterdir(tmp_path) == []


def test_safe_iterdir_permissionerror_returns_empty(tmp_path: Path) -> None:
    """Locked ACLs are normal in a collected image and must not end the walk."""
    with patch.object(Path, "iterdir", side_effect=PermissionError("access denied")):
        assert safe_iterdir(tmp_path) == []


def test_resolve_oversized_path_returns_root_without_raising(tmp_path: Path) -> None:
    """An oversized Windows path resolves to the image root instead of raising."""
    filesystem = FilesystemHelper(image_root=tmp_path)
    assert filesystem.resolve("C:\\" + "A" * 40000) == tmp_path


def test_resolve_nul_in_path_returns_root_without_raising(tmp_path: Path) -> None:
    """A path containing an embedded NUL resolves to the image root, not an error."""
    filesystem = FilesystemHelper(image_root=tmp_path)
    assert filesystem.resolve("C:\\evil\x00payload.exe") == tmp_path


def _over_limit(prefix: str) -> str:
    """Build a path string past the length at which Win32 starts refusing."""
    text = prefix
    while len(text) < _LONG_PATH_LIMIT + 40:
        text += "\\" + "d" * 40
    return text


# io_path is a pure string transformation, so PureWindowsPath exercises the
# Windows semantics on the Linux and macOS CI runners too.


def test_io_path_leaves_short_path_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ordinary paths pass through untouched, so the prefix never reaches logs."""
    monkeypatch.setattr("pyrsistencesniper.core.windows.on_windows", lambda: True)
    path = PureWindowsPath(r"C:\Windows\System32\cmd.exe")
    assert io_path(path) is path


def test_io_path_prefixes_long_absolute_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Past the limit the prefix is what keeps Win32 from reporting the file absent."""
    monkeypatch.setattr("pyrsistencesniper.core.windows.on_windows", lambda: True)
    prefixed = io_path(PureWindowsPath(_over_limit("C:")))
    assert str(prefixed).startswith("\\\\?\\C:")


def test_io_path_leaves_relative_path_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """The prefix only means anything on a fully qualified path."""
    monkeypatch.setattr("pyrsistencesniper.core.windows.on_windows", lambda: True)
    path = PureWindowsPath(_over_limit("relative"))
    assert io_path(path) is path


def test_io_path_leaves_dot_dot_path_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """The prefix disables normalization, so ".." would stop being resolved."""
    monkeypatch.setattr("pyrsistencesniper.core.windows.on_windows", lambda: True)
    path = PureWindowsPath(_over_limit("C:") + "\\..\\payload.exe")
    assert io_path(path) is path


def test_io_path_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prefixing twice would produce an invalid path, so the call is repeatable."""
    monkeypatch.setattr("pyrsistencesniper.core.windows.on_windows", lambda: True)
    once = io_path(PureWindowsPath(_over_limit("C:")))
    assert io_path(once) is once


def test_io_path_uses_the_unc_form_for_network_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A share needs the UNC spelling; the plain prefix would name a missing drive."""
    monkeypatch.setattr("pyrsistencesniper.core.windows.on_windows", lambda: True)
    prefixed = io_path(PureWindowsPath(_over_limit("\\\\server\\share")))
    assert str(prefixed).startswith("\\\\?\\UNC\\server\\share")


def test_io_path_is_a_no_op_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only Win32 has the limit, and the prefix would corrupt a POSIX path."""
    monkeypatch.setattr("pyrsistencesniper.core.windows.on_windows", lambda: False)
    path = PureWindowsPath(_over_limit("C:"))
    assert io_path(path) is path


def _long_paths_enabled() -> bool:
    """Report whether this host has had Win32's MAX_PATH limit lifted."""
    # GitHub's windows runners ship with this turned on, so the precondition
    # below is only true where the limit still bites. The rest of the test
    # holds either way, which is why this gates one assert and not the test.
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\FileSystem",
        ) as key:
            return bool(winreg.QueryValueEx(key, "LongPathsEnabled")[0])
    except OSError:
        return False


@pytest.mark.skipif(os.name != "nt", reason="long-path prefixing is Windows-only")
def test_over_length_tree_is_readable(tmp_path: Path) -> None:
    """A file past MAX_PATH is found and hashed rather than read as absent."""
    # With LongPathsEnabled at 0 every call below reports "not found", which is
    # indistinguishable from a file the collection never captured.
    deep = tmp_path
    while len(str(deep)) < 300:
        deep = deep / ("d" * 40)
        Path("\\\\?\\" + str(deep)).mkdir()
    payload = deep / "payload.exe"
    with Path("\\\\?\\" + str(payload)).open("wb") as handle:
        handle.write(b"persistence")

    if not _long_paths_enabled():
        assert not payload.is_file(), "precondition: plain pathlib cannot see it"

    filesystem = FilesystemHelper(tmp_path)
    windows_path = "C:\\" + str(payload.relative_to(tmp_path))
    assert filesystem.exists(windows_path)
    assert filesystem.sha256(windows_path) == hashlib.sha256(b"persistence").hexdigest()
    assert [entry.name for entry in safe_iterdir(deep)] == ["payload.exe"]


def test_read_bounded_returns_a_file_within_the_limit(tmp_path: Path) -> None:
    """A file no larger than the limit is read whole."""
    target = tmp_path / "small.bin"
    target.write_bytes(b"12345678")

    assert read_bounded(target, 8) == b"12345678"


def test_read_bounded_refuses_a_file_over_the_limit(tmp_path: Path) -> None:
    """An image names its own file sizes, so an oversized file is never read whole."""
    target = tmp_path / "large.bin"
    target.write_bytes(b"123456789")

    with pytest.raises(ValueError, match="exceeds 8 bytes"):
        read_bounded(target, 8)


def test_read_bounded_leaves_a_missing_file_to_the_caller(tmp_path: Path) -> None:
    """Absence stays an OSError, so a caller can tell it from an oversized file."""
    with pytest.raises(FileNotFoundError):
        read_bounded(tmp_path / "absent.bin", 8)
