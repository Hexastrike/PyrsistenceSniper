"""Tests for the $MFT index: path normalisation, discovery, and lookup."""

from __future__ import annotations

import io
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.timeline import mft_index as mft_index_module
from pyrsistencesniper.timeline.mft import MftEntry
from pyrsistencesniper.timeline.mft_index import MftIndex, normalize_image_path


def test_normalize_strips_drive_and_casefolds() -> None:
    """$MFT records carry no drive letter and no fixed case, so both are dropped."""
    assert normalize_image_path("C:\\Windows\\Evil.EXE") == "windows\\evil.exe"


def test_normalize_strips_device_prefix() -> None:
    """Long-path prefixes appear in collected paths and must not defeat matching."""
    assert normalize_image_path("\\\\?\\C:\\A\\B") == "a\\b"


def test_normalize_converts_forward_slashes() -> None:
    """Forward slashes are a legal Windows separator and must still match records."""
    assert normalize_image_path("Windows/System32/x") == "windows\\system32\\x"


def _entry(path: str) -> MftEntry:
    """Build an MftEntry at the given path with only si_modified populated."""
    return MftEntry(
        record_number=1,
        path=path,
        si_created=None,
        si_modified=datetime(2026, 7, 20, tzinfo=UTC),
        fn_created=None,
        fn_modified=None,
    )


@pytest.fixture
def _stub_parse(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Stub parse_mft with one canned entry and return the log of its calls."""
    calls: list[int] = []

    def fake_parse(handle: io.BufferedReader) -> list[MftEntry]:
        """Record the call and return a single canned Tasks entry."""
        calls.append(1)
        return [_entry("Windows\\System32\\Tasks\\Evil")]

    monkeypatch.setattr(mft_index_module, "parse_mft", fake_parse)
    return calls


def _image(tmp_path: Path) -> Path:
    """Create an image root nested one level down, away from sibling temp dirs."""
    # $MFT discovery scans the parent, so nest the root to keep sibling dirs out.
    root = tmp_path / "img"
    root.mkdir()
    return root


def test_explicit_path_wins(tmp_path: Path, _stub_parse: list[int]) -> None:
    """An operator-supplied --mft path is used even when it is outside the image."""
    root = _image(tmp_path)
    mft_file = tmp_path / "external.mft"
    mft_file.write_bytes(b"data")
    index = MftIndex(FilesystemHelper(root), explicit_path=mft_file)
    hit = index.lookup("C:\\Windows\\System32\\Tasks\\Evil")
    assert hit is not None
    assert hit.si_modified is not None


def test_discovers_mft_at_image_root(tmp_path: Path, _stub_parse: list[int]) -> None:
    """A $MFT sitting beside the hives needs no --mft flag."""
    root = _image(tmp_path)
    (root / "$MFT").write_bytes(b"data")
    index = MftIndex(FilesystemHelper(root))
    assert index.lookup("Windows\\System32\\Tasks\\Evil") is not None


def test_discovers_percent_encoded_mft_in_subdir(
    tmp_path: Path, _stub_parse: list[int]
) -> None:
    """Collection tools percent-escape the $ and nest the file; discovery copes."""
    root = _image(tmp_path)
    sub = tmp_path / "mftdir"
    sub.mkdir()
    (sub / "%24MFT").write_bytes(b"data")
    index = MftIndex(FilesystemHelper(root))
    assert index.lookup("Windows\\System32\\Tasks\\Evil") is not None


def test_index_built_once(tmp_path: Path, _stub_parse: list[int]) -> None:
    """Parsing a multi-gigabyte $MFT twice would cost a scan its runtime."""
    root = _image(tmp_path)
    (root / "$MFT").write_bytes(b"data")
    index = MftIndex(FilesystemHelper(root))
    index.lookup("a")
    index.lookup("b")
    assert len(_stub_parse) == 1


def test_no_mft_yields_no_hits(tmp_path: Path, _stub_parse: list[int]) -> None:
    """No $MFT is a clean absence: lookups miss and no parse is attempted."""
    root = _image(tmp_path)
    index = MftIndex(FilesystemHelper(root))
    assert index.lookup("Windows\\x") is None
    assert len(_stub_parse) == 0


def test_percent_decoded_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unescaped path resolves on the direct key, before the decoding retry."""

    def fake_parse(handle: io.BufferedReader) -> list[MftEntry]:
        """Return one entry for the WMI repository OBJECTS.DATA file."""
        return [_entry("Windows\\System32\\wbem\\Repository\\OBJECTS.DATA")]

    monkeypatch.setattr(mft_index_module, "parse_mft", fake_parse)
    root = _image(tmp_path)
    (root / "$MFT").write_bytes(b"data")
    index = MftIndex(FilesystemHelper(root))
    hit = index.lookup("Windows\\System32\\wbem\\Repository\\OBJECTS.DATA")
    assert hit is not None
