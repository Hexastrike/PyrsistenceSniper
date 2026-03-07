from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from pyrsistencesniper.core.lolbins import (
    _load_bundled,
    _load_cache,
    load_lolbin_names,
)


def test_load_bundled_returns_nonempty_frozenset() -> None:
    """The bundled snapshot should contain known LOLBin names."""
    names = _load_bundled()
    assert isinstance(names, frozenset)
    assert len(names) > 0
    # mshta.exe is a classic LOLBin
    assert "mshta.exe" in names


def test_load_cache_returns_none_when_missing(tmp_path: Path) -> None:
    """If no cache file exists, _load_cache returns None."""
    with patch(
        "pyrsistencesniper.core.lolbins._CACHE_FILE",
        tmp_path / "nonexistent.json",
    ):
        assert _load_cache() is None


def test_load_cache_returns_frozenset(tmp_path: Path) -> None:
    """A valid cache file should parse to a frozenset."""
    cache = tmp_path / "lolbins.json"
    cache.write_text(json.dumps(["mshta.exe", "certutil.exe"]))
    with patch("pyrsistencesniper.core.lolbins._CACHE_FILE", cache):
        result = _load_cache()
    assert result is not None
    assert "mshta.exe" in result
    assert "certutil.exe" in result


def test_load_cache_returns_none_on_corrupt(tmp_path: Path) -> None:
    """A corrupt cache file should return None, not raise."""
    cache = tmp_path / "lolbins.json"
    cache.write_text("not json")
    with patch("pyrsistencesniper.core.lolbins._CACHE_FILE", cache):
        assert _load_cache() is None


def test_load_lolbin_names_prefers_cache() -> None:
    """load_lolbin_names should prefer cache over bundled."""
    cache_names = frozenset({"custom.exe"})
    with patch(
        "pyrsistencesniper.core.lolbins._load_cache",
        return_value=cache_names,
    ):
        result = load_lolbin_names()
    assert result is cache_names


def test_load_lolbin_names_falls_back_to_bundled() -> None:
    """load_lolbin_names should fall back to bundled when no cache."""
    with patch(
        "pyrsistencesniper.core.lolbins._load_cache",
        return_value=None,
    ):
        result = load_lolbin_names()
    assert isinstance(result, frozenset)
    assert len(result) > 0
