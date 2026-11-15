"""Tests for the tri-state path probes and the skip ledger they feed."""

from __future__ import annotations

import errno
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from pyrsistencesniper.core.filesystem import (
    FilesystemHelper,
    _is_reparse_point,
    safe_exists,
    safe_is_dir,
    safe_is_file,
    safe_iterdir,
)
from pyrsistencesniper.core.ledger import reset, skipped_paths

# The failure that ended a whole scan of an FTK-mounted image: four legacy
# reparse points answered every probe with it, and pathlib re-raises errno 22.
# A virtual-disk driver raises it, so every error here is injected, never staged.
WINERROR_FILE_CORRUPT = 1392
CORRUPTION_MESSAGE = "The file or directory is corrupted and unreadable"


def _corruption_error() -> OSError:
    """Build the error a mounted image raises on a path it cannot read."""
    # Only Win32 carries a winerror; the production code branches on errno either way.
    if os.name == "nt":
        return OSError(errno.EINVAL, CORRUPTION_MESSAGE, None, WINERROR_FILE_CORRUPT)
    return OSError(errno.EINVAL, CORRUPTION_MESSAGE)


# --- The probes answer correctly when the filesystem is readable -------------


def test_safe_is_file_true_for_a_real_file(tmp_path: Path) -> None:
    """A collected file reads as present, the ordinary case the scan depends on."""
    payload = tmp_path / "payload.exe"
    payload.write_bytes(b"persistence")
    assert safe_is_file(payload) is True


def test_safe_is_file_false_for_a_directory(tmp_path: Path) -> None:
    """A directory is not something a persistence entry can execute."""
    config = tmp_path / "config"
    config.mkdir()
    assert safe_is_file(config) is False


def test_safe_is_file_false_for_a_missing_path(tmp_path: Path) -> None:
    """An uncollected path is a plain absence, and False is the evidence of it."""
    assert safe_is_file(tmp_path / "nonexistent.exe") is False


def test_safe_is_dir_true_for_a_real_directory(tmp_path: Path) -> None:
    """A directory the image contains reads as one."""
    startup = tmp_path / "Startup"
    startup.mkdir()
    assert safe_is_dir(startup) is True


def test_safe_is_dir_false_for_a_file(tmp_path: Path) -> None:
    """A file is not a directory, and the walk must not try to descend into it."""
    payload = tmp_path / "payload.exe"
    payload.write_bytes(b"persistence")
    assert safe_is_dir(payload) is False


def test_safe_is_dir_false_for_a_missing_path(tmp_path: Path) -> None:
    """A directory the collection never captured is absent, not undeterminable."""
    assert safe_is_dir(tmp_path / "Startup") is False


def test_safe_exists_true_for_a_real_file(tmp_path: Path) -> None:
    """Existence covers files, which is the common subject of an image check."""
    payload = tmp_path / "payload.exe"
    payload.write_bytes(b"persistence")
    assert safe_exists(payload) is True


def test_safe_exists_true_for_a_real_directory(tmp_path: Path) -> None:
    """Existence covers directories too, unlike the file-only probe."""
    startup = tmp_path / "Startup"
    startup.mkdir()
    assert safe_exists(startup) is True


def test_safe_exists_false_for_a_missing_path(tmp_path: Path) -> None:
    """Nothing at the path means False, the answer downstream treats as evidence."""
    assert safe_exists(tmp_path / "nonexistent.exe") is False


# --- The probes answer None when the filesystem refuses ----------------------


def test_safe_is_file_returns_none_when_the_probe_raises(tmp_path: Path) -> None:
    """An unreadable path is not a missing one, so it must never answer False."""
    with patch.object(Path, "is_file", side_effect=_corruption_error()):
        assert safe_is_file(tmp_path / "corrupt.lnk") is None


def test_safe_is_dir_returns_none_when_the_probe_raises(tmp_path: Path) -> None:
    """A directory that will not open leaves its contents unknown, not empty."""
    with patch.object(Path, "is_dir", side_effect=_corruption_error()):
        assert safe_is_dir(tmp_path / "corrupt") is None


def test_safe_exists_returns_none_when_the_probe_raises(tmp_path: Path) -> None:
    """Existence is undeterminable when the platform refuses to answer at all."""
    with patch.object(Path, "exists", side_effect=_corruption_error()):
        assert safe_exists(tmp_path / "corrupt.lnk") is None


def test_probe_failure_does_not_escape_as_an_exception(tmp_path: Path) -> None:
    """One bad entry ended the whole scan before this; it must stay contained."""
    with patch.object(Path, "is_file", side_effect=_corruption_error()):
        results = [safe_is_file(tmp_path / f"corrupt{index}.lnk") for index in range(4)]
    assert results == [None, None, None, None]


@pytest.mark.skipif(os.name != "nt", reason="only Win32 errors carry a winerror")
def test_injected_error_names_winerror_1392() -> None:
    """The injected failure is the real one, not a stand-in with the wrong shape."""
    error = _corruption_error()
    assert error.winerror == WINERROR_FILE_CORRUPT
    assert error.errno == errno.EINVAL


# --- The ledger records coverage loss, and only coverage loss ----------------


def test_unreadable_path_is_recorded_in_the_ledger(tmp_path: Path) -> None:
    """A path the scan could not read is coverage lost, and must leave the scan."""
    target = tmp_path / "corrupt.lnk"
    target.write_bytes(b"")
    with patch.object(Path, "is_file", side_effect=_corruption_error()):
        safe_is_file(target)
    assert str(target) in skipped_paths()


def test_recorded_skip_names_the_error_type_and_message(tmp_path: Path) -> None:
    """The record has to say what refused, or the reader cannot judge the gap."""
    target = tmp_path / "corrupt.lnk"
    target.write_bytes(b"")
    with patch.object(Path, "is_file", side_effect=_corruption_error()):
        safe_is_file(target)
    recorded = skipped_paths()[str(target)]
    assert recorded.startswith("OSError: ")
    assert CORRUPTION_MESSAGE in recorded


def test_missing_path_error_records_no_skip(tmp_path: Path) -> None:
    """ENOENT is a plain absence, not lost coverage, and must not inflate the gap."""
    absent = tmp_path / "nonexistent.exe"
    with patch.object(
        Path, "is_file", side_effect=FileNotFoundError(errno.ENOENT, "not found")
    ):
        result = safe_is_file(absent)
    assert result is None
    assert skipped_paths() == {}


def test_not_a_directory_error_records_no_skip(tmp_path: Path) -> None:
    """A path under a file names nothing; that is absence too, not a read failure."""
    under_a_file = tmp_path / "payload.exe" / "child.dll"
    with patch.object(
        Path, "is_file", side_effect=NotADirectoryError(errno.ENOTDIR, "not a dir")
    ):
        result = safe_is_file(under_a_file)
    assert result is None
    assert skipped_paths() == {}


def test_reparse_point_records_no_skip(tmp_path: Path) -> None:
    """A junction that will not open costs nothing: its target is read by name."""
    junction = tmp_path / "Documents and Settings"
    with (
        patch("pyrsistencesniper.core.filesystem._is_reparse_point", return_value=True),
        patch.object(Path, "is_dir", side_effect=_corruption_error()),
    ):
        result = safe_is_dir(junction)
    assert result is None
    assert skipped_paths() == {}


def test_reset_empties_the_ledger(tmp_path: Path) -> None:
    """Each scan reports its own coverage, so the ledger starts every scan empty."""
    target = tmp_path / "corrupt.lnk"
    target.write_bytes(b"")
    with patch.object(Path, "is_file", side_effect=_corruption_error()):
        safe_is_file(target)
    assert skipped_paths() != {}
    reset()
    assert skipped_paths() == {}


def test_skipped_paths_returns_a_copy(tmp_path: Path) -> None:
    """Callers report the ledger; editing what they get must not edit the scan's."""
    target = tmp_path / "corrupt.lnk"
    target.write_bytes(b"")
    with patch.object(Path, "is_file", side_effect=_corruption_error()):
        safe_is_file(target)
    snapshot = skipped_paths()
    snapshot.clear()
    assert str(target) in skipped_paths()


# --- Directory listing feeds the same ledger ---------------------------------


def test_safe_iterdir_records_a_skip_for_an_unreadable_directory(
    tmp_path: Path,
) -> None:
    """A directory that will not enumerate hides whatever it held, and says so."""
    with patch.object(Path, "iterdir", side_effect=_corruption_error()):
        entries = safe_iterdir(tmp_path)
    assert entries == []
    assert str(tmp_path) in skipped_paths()


def test_safe_iterdir_records_no_skip_for_a_missing_directory(tmp_path: Path) -> None:
    """A directory the image never had is an absence the report should not carry."""
    absent = tmp_path / "Startup"
    with patch.object(
        Path, "iterdir", side_effect=FileNotFoundError(errno.ENOENT, "not found")
    ):
        entries = safe_iterdir(absent)
    assert entries == []
    assert skipped_paths() == {}


def test_safe_iterdir_leaves_no_skip_for_a_readable_directory(tmp_path: Path) -> None:
    """A clean listing is not a gap, and must leave the ledger untouched."""
    (tmp_path / "a.txt").write_text("a")
    assert [entry.name for entry in safe_iterdir(tmp_path)] == ["a.txt"]
    assert skipped_paths() == {}


# --- FilesystemHelper.exists carries the tri-state through --------------------


def test_helper_exists_true_for_a_collected_file(tmp_path: Path) -> None:
    """The Windows-path front door still answers True for a file that is there."""
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SOFTWARE").write_bytes(b"\x00" * 16)
    filesystem = FilesystemHelper(tmp_path)
    assert filesystem.exists("C:\\Windows\\System32\\config\\SOFTWARE") is True


def test_helper_exists_false_for_an_uncollected_file(tmp_path: Path) -> None:
    """Absence keeps its own answer; only unreadability gets the third one."""
    filesystem = FilesystemHelper(tmp_path)
    assert filesystem.exists("C:\\Windows\\System32\\nonexistent.exe") is False


def test_helper_exists_none_when_the_path_cannot_be_probed(tmp_path: Path) -> None:
    """False here would be a plugin's evidence of absence, fabricated from a fault."""
    filesystem = FilesystemHelper(tmp_path)
    with patch.object(Path, "is_file", side_effect=_corruption_error()):
        result = filesystem.exists("C:\\Windows\\System32\\corrupt.dll")
    assert result is None
    assert result is not False


def test_helper_exists_records_the_resolved_path_as_skipped(tmp_path: Path) -> None:
    """The ledger names the host path, which is what a reader can go and check."""
    filesystem = FilesystemHelper(tmp_path)
    with patch.object(Path, "is_file", side_effect=_corruption_error()):
        filesystem.exists("C:\\Windows\\System32\\corrupt.dll")
    expected = tmp_path / "Windows" / "System32" / "corrupt.dll"
    assert str(expected) in skipped_paths()


# --- Reparse-point detection --------------------------------------------------


def test_is_reparse_point_false_for_a_plain_directory(tmp_path: Path) -> None:
    """An ordinary directory is real storage, so a failure to read it is a gap."""
    plain = tmp_path / "System32"
    plain.mkdir()
    assert _is_reparse_point(plain) is False


def test_is_reparse_point_false_for_a_missing_path(tmp_path: Path) -> None:
    """A name with no directory entry carries no attributes to read."""
    assert _is_reparse_point(tmp_path / "nonexistent.exe") is False


def test_is_reparse_point_false_when_scandir_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The parent may be as unreadable as the child; that is not a licence to skip."""
    monkeypatch.setattr("pyrsistencesniper.core.filesystem._on_windows", lambda: True)
    with patch.object(os, "scandir", side_effect=_corruption_error()):
        assert _is_reparse_point(tmp_path / "corrupt.lnk") is False


@pytest.mark.skipif(os.name != "nt", reason="reparse points are a Windows concept")
def test_is_reparse_point_true_for_a_symlink(tmp_path: Path) -> None:
    """A real reparse point is recognised from the parent's index, unopened."""
    target = tmp_path / "target.txt"
    target.write_text("payload")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation needs developer mode or elevation")
    assert _is_reparse_point(link) is True
