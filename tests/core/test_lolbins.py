"""Tests for LOLBin name loading: bundled snapshot, cache file, and fallback."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from pyrsistencesniper.core.lolbins import (
    _fetch_payload,
    _load_bundled,
    _load_cache,
    download_lolbins,
    load_lolbin_names,
)


def test_load_bundled_returns_nonempty_frozenset() -> None:
    """A release detects LOLBins offline, with no fetched list behind it."""
    names = _load_bundled()
    assert isinstance(names, frozenset)
    assert len(names) > 0
    assert "mshta.exe" in names


def test_load_cache_returns_none_when_missing(tmp_path: Path) -> None:
    """A first run has no cache yet, which is the normal state and not a failure."""
    with patch(
        "pyrsistencesniper.core.lolbins._CACHE_FILE",
        tmp_path / "nonexistent.json",
    ):
        assert _load_cache() is None


def test_load_cache_returns_frozenset(tmp_path: Path) -> None:
    """A refreshed list is read back, so a new LOLBin counts before a release."""
    cache = tmp_path / "lolbins.json"
    cache.write_text(json.dumps(["mshta.exe", "certutil.exe"]))
    with patch("pyrsistencesniper.core.lolbins._CACHE_FILE", cache):
        result = _load_cache()
    assert result is not None
    assert "mshta.exe" in result
    assert "certutil.exe" in result


def test_load_cache_returns_none_on_corrupt(tmp_path: Path) -> None:
    """A truncated cache is discarded rather than raised inside the scan."""
    cache = tmp_path / "lolbins.json"
    cache.write_text("not json")
    with patch("pyrsistencesniper.core.lolbins._CACHE_FILE", cache):
        assert _load_cache() is None


def test_load_lolbin_names_prefers_cache() -> None:
    """A refreshed cache wins, so list updates take effect without a release."""
    cache_names = frozenset({"custom.exe"})
    with patch(
        "pyrsistencesniper.core.lolbins._load_cache",
        return_value=cache_names,
    ):
        result = load_lolbin_names()
    assert result is cache_names


def test_load_lolbin_names_falls_back_to_bundled() -> None:
    """A machine that never fetched the list still gets LOLBin detection."""
    with patch(
        "pyrsistencesniper.core.lolbins._load_cache",
        return_value=None,
    ):
        result = load_lolbin_names()
    assert isinstance(result, frozenset)
    assert len(result) > 0


_LOLBAS = "pyrsistencesniper.core.lolbins"


def test_download_persists_the_names_to_the_cache(tmp_path: Path) -> None:
    """A fetched list is written lowercased, so the next scan reads it offline."""
    cache_file = tmp_path / "cache" / "lolbins.json"
    payload = [{"Name": "Mshta.exe"}, {"Name": " "}, "not an entry"]

    with (
        patch(f"{_LOLBAS}._fetch_payload", return_value=payload),
        patch(f"{_LOLBAS}._CACHE_DIR", cache_file.parent),
        patch(f"{_LOLBAS}._CACHE_FILE", cache_file),
    ):
        assert download_lolbins() == {"mshta.exe"}

    assert json.loads(cache_file.read_text(encoding="utf-8")) == ["mshta.exe"]


def test_download_retries_a_failed_fetch(tmp_path: Path) -> None:
    """One dropped connection must not cost the update."""
    cache_file = tmp_path / "lolbins.json"
    attempts = [OSError("connection reset"), [{"Name": "certutil.exe"}]]

    with (
        patch(f"{_LOLBAS}._fetch_payload", side_effect=attempts),
        patch(f"{_LOLBAS}.time.sleep"),
        patch(f"{_LOLBAS}._CACHE_DIR", tmp_path),
        patch(f"{_LOLBAS}._CACHE_FILE", cache_file),
    ):
        assert download_lolbins() == {"certutil.exe"}


def test_fetch_refuses_an_oversized_payload() -> None:
    """The response is capped, so a hostile mirror cannot fill memory."""
    response = MagicMock()
    response.__enter__.return_value.read.return_value = b"x" * 9

    with (
        patch(f"{_LOLBAS}.urllib.request.urlopen", return_value=response),
        patch(f"{_LOLBAS}._MAX_PAYLOAD_BYTES", 8),
        pytest.raises(ValueError, match="exceeds 8 bytes"),
    ):
        _fetch_payload()
