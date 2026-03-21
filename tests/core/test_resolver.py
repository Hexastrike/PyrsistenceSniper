"""Tests for core/resolver.py — ResolutionPipeline and SignerExtractor."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, create_autospec, patch

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.models import Finding
from pyrsistencesniper.core.resolver import ResolutionPipeline, SignerExtractor


def _make_pipeline(
    exists: bool = False,
    sha256: str = "",
) -> ResolutionPipeline:
    fs = create_autospec(FilesystemHelper, instance=True)
    fs.exists.return_value = exists
    fs.sha256.return_value = sha256
    fs.resolve.side_effect = lambda p: Path("/fake") / p
    return ResolutionPipeline(fs)


# -- resolve fills fields -----------------------------------------------------


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_lolbin(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="mshta.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is True


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_builtin(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="explorer.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_builtin is True


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_non_lolbin_non_builtin(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="custom_app.exe")
    assert finding.is_lolbin is None
    assert finding.is_builtin is None
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is False
    assert resolved.is_builtin is False


# -- caching ------------------------------------------------------------------


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_caches_by_path(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    f1 = Finding(value="mshta.exe", path="HKLM\\Run")
    f2 = Finding(value="mshta.exe", path="HKLM\\RunOnce")
    r1 = pipeline.resolve(f1)
    r2 = pipeline.resolve(f2)
    assert r1.is_lolbin == r2.is_lolbin is True


# -- skip already set ---------------------------------------------------------


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_skips_already_set_fields(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="explorer.exe", is_builtin=True, is_lolbin=True)
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is True
    assert resolved.is_builtin is True


# -- tri-state logic ----------------------------------------------------------


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_respects_explicit_false_exists(_mock_signer: MagicMock) -> None:
    """A plugin that explicitly sets exists=False should not be overwritten."""
    pipeline = _make_pipeline(exists=True)
    finding = Finding(value="explorer.exe", exists=False)
    resolved = pipeline.resolve(finding)
    assert resolved.exists is False


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_respects_explicit_false_is_lolbin(_mock_signer: MagicMock) -> None:
    """A plugin that explicitly sets is_lolbin=False should not be overwritten."""
    pipeline = _make_pipeline()
    finding = Finding(value="mshta.exe", is_lolbin=False)
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is False


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_respects_explicit_false_is_builtin(_mock_signer: MagicMock) -> None:
    """A plugin that explicitly sets is_builtin=False should not be overwritten."""
    pipeline = _make_pipeline()
    finding = Finding(value="explorer.exe", is_builtin=False)
    resolved = pipeline.resolve(finding)
    assert resolved.is_builtin is False


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_fills_none_fields(_mock_signer: MagicMock) -> None:
    """Default None fields should be filled by the resolver."""
    pipeline = _make_pipeline(exists=True)
    finding = Finding(value="mshta.exe")
    assert finding.is_lolbin is None
    assert finding.is_builtin is None
    assert finding.exists is None
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is True
    assert resolved.is_builtin is False
    assert resolved.exists is True


# -- new tests: exists & sha256 via mock -------------------------------------


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_fills_exists_true(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline(exists=True)
    finding = Finding(value="notepad.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.exists is True


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_fills_exists_false(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline(exists=False)
    finding = Finding(value="notepad.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.exists is False


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_fills_sha256(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline(exists=True, sha256="abc123def456")
    finding = Finding(value="notepad.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.sha256 == "abc123def456"


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_extracts_executable_from_cmdline(_mock_signer: MagicMock) -> None:
    """cmd /c malware.exe — the resolver should extract malware.exe, not cmd."""
    pipeline = _make_pipeline()
    finding = Finding(value="cmd /c malware.exe")
    resolved = pipeline.resolve(finding)
    # cmd.exe is a lolbin and builtin; malware.exe is neither
    assert resolved.is_lolbin is False
    assert resolved.is_builtin is False


# -- case-insensitive cache ---------------------------------------------------


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_case_insensitive_cache(_mock_signer: MagicMock) -> None:
    """cmd.exe and CMD.EXE should share a single cache entry."""
    pipeline = _make_pipeline(exists=True)
    f1 = Finding(value="cmd.exe", path="HKLM\\Run")
    f2 = Finding(value="CMD.EXE", path="HKLM\\RunOnce")
    pipeline.resolve(f1)
    initial_count = pipeline._fs.exists.call_count
    pipeline.resolve(f2)
    # Second resolve should not trigger any additional exists calls (cache hit)
    assert pipeline._fs.exists.call_count == initial_count


# -- skip sha256/signer when not exists ----------------------------------------


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_skips_sha256_when_not_exists(_mock_signer: MagicMock) -> None:
    """When file doesn't exist, sha256 should be skipped."""
    pipeline = _make_pipeline(exists=False)
    finding = Finding(value="missing.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.exists is False
    assert resolved.sha256 == ""
    # sha256 should not be called when file doesn't exist
    pipeline._fs.sha256.assert_not_called()


# -- is_in_os_directory -------------------------------------------------------


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_in_os_directory_true(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="C:\\Windows\\System32\\svchost.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is True


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_in_os_directory_false(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="C:\\Users\\test\\malware.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is False


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_in_os_directory_subdirectory(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="C:\\Windows\\System32\\drivers\\srv.sys")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is True


@patch("pyrsistencesniper.core.resolver.SignerExtractor.extract", return_value="")
def test_resolve_bare_dll_fallback_to_system32(_mock_signer: MagicMock) -> None:
    """Bare DLL names like ifmon.dll should resolve to System32."""
    fs = create_autospec(FilesystemHelper, instance=True)
    # First call: bare name check, second: System32 path exists
    fs.exists.side_effect = lambda p: p == "Windows\\System32\\ifmon.dll"
    fs.sha256.return_value = ""
    fs.resolve.side_effect = lambda p: Path("/fake") / p
    pipeline = ResolutionPipeline(fs)
    finding = Finding(value="ifmon.dll")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is True


# -- SignerExtractor -----------------------------------------------------------


class TestExtract:
    """Tests for SignerExtractor.extract()."""

    def test_extract_returns_empty_when_signify_unavailable(
        self, tmp_path: Path
    ) -> None:
        """extract() returns '' when signify is not installed."""
        fs = FilesystemHelper(image_root=tmp_path)
        extractor = SignerExtractor(fs)
        with patch("pyrsistencesniper.core.resolver._HAS_SIGNIFY", False):
            result = extractor.extract("C:\\Windows\\System32\\cmd.exe")
        assert result == "", "Should return empty string when signify unavailable"

    def test_extract_returns_empty_for_nonexistent_file(self, tmp_path: Path) -> None:
        """extract() returns '' when the resolved path does not exist."""
        fs = FilesystemHelper(image_root=tmp_path)
        extractor = SignerExtractor(fs)
        with patch("pyrsistencesniper.core.resolver._HAS_SIGNIFY", True):
            result = extractor.extract("C:\\nonexistent\\file.exe")
        assert result == "", "Should return empty string for nonexistent file"

    def test_extract_returns_program_name_from_signature(self, tmp_path: Path) -> None:
        """extract() returns the program_name from a valid PE signature."""
        # Create a dummy PE file
        pe_file = tmp_path / "Windows" / "System32" / "cmd.exe"
        pe_file.parent.mkdir(parents=True, exist_ok=True)
        pe_file.write_bytes(b"MZ fake PE content")

        fs = FilesystemHelper(image_root=tmp_path)
        extractor = SignerExtractor(fs)

        mock_signer_info = MagicMock()
        mock_signer_info.program_name = "Microsoft Windows"

        mock_signature = MagicMock()
        mock_signature.signer_info = mock_signer_info

        mock_pe = MagicMock()
        mock_pe.iter_signatures.return_value = [mock_signature]

        with (
            patch("pyrsistencesniper.core.resolver._HAS_SIGNIFY", True),
            patch(
                "pyrsistencesniper.core.resolver.SignedPEFile",
                return_value=mock_pe,
            ),
        ):
            result = extractor.extract("C:\\Windows\\System32\\cmd.exe")
        assert result == "Microsoft Windows", (
            "Should return program_name from PE signature"
        )

    def test_extract_falls_through_to_catalog_lookup(self, tmp_path: Path) -> None:
        """extract() calls _lookup_in_catalogs when PE has no direct signature."""
        pe_file = tmp_path / "Windows" / "System32" / "notepad.exe"
        pe_file.parent.mkdir(parents=True, exist_ok=True)
        pe_file.write_bytes(b"MZ fake PE")

        fs = FilesystemHelper(image_root=tmp_path)
        extractor = SignerExtractor(fs)

        mock_pe = MagicMock()
        mock_pe.iter_signatures.return_value = []  # No direct signatures

        with (
            patch("pyrsistencesniper.core.resolver._HAS_SIGNIFY", True),
            patch(
                "pyrsistencesniper.core.resolver.SignedPEFile",
                return_value=mock_pe,
            ),
            patch.object(
                extractor,
                "_lookup_in_catalogs",
                return_value="Catalog Signer",
            ) as mock_lookup,
        ):
            result = extractor.extract("C:\\Windows\\System32\\notepad.exe")
        (
            mock_lookup.assert_called_once_with(mock_pe),
            ("_lookup_in_catalogs should be called when no direct signature"),
        )
        assert result == "Catalog Signer", "Should return result from catalog lookup"

    def test_extract_returns_empty_on_exception(self, tmp_path: Path) -> None:
        """extract() returns '' when PE parsing raises an exception."""
        pe_file = tmp_path / "Windows" / "bad.exe"
        pe_file.parent.mkdir(parents=True, exist_ok=True)
        pe_file.write_bytes(b"MZ corrupt")

        fs = FilesystemHelper(image_root=tmp_path)
        extractor = SignerExtractor(fs)

        with (
            patch("pyrsistencesniper.core.resolver._HAS_SIGNIFY", True),
            patch(
                "pyrsistencesniper.core.resolver.SignedPEFile",
                side_effect=RuntimeError("parse failed"),
            ),
        ):
            result = extractor.extract("C:\\Windows\\bad.exe")
        assert result == "", (
            "Should return empty string when PE parsing raises exception"
        )


class TestCatalogLoading:
    """Tests for catalog file loading and caching."""

    def test_load_catalog_data_returns_empty_for_missing_dir(
        self, tmp_path: Path
    ) -> None:
        """_load_catalog_data returns [] when CatRoot dir does not exist."""
        fs = FilesystemHelper(image_root=tmp_path)
        extractor = SignerExtractor(fs)
        result = extractor._load_catalog_data()
        assert result == [], "Should return empty list when CatRoot directory missing"

    def test_load_catalog_data_reads_cat_files(self, tmp_path: Path) -> None:
        """_load_catalog_data reads .cat files from the CatRoot directory."""
        cat_dir = (
            tmp_path
            / "Windows"
            / "System32"
            / "CatRoot"
            / "{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"
        )
        cat_dir.mkdir(parents=True)
        (cat_dir / "test1.cat").write_bytes(b"catalog-data-1")
        (cat_dir / "test2.cat").write_bytes(b"catalog-data-2")

        fs = FilesystemHelper(image_root=tmp_path)
        extractor = SignerExtractor(fs)
        result = extractor._load_catalog_data()
        assert len(result) == 2, "Should read both .cat files"
        assert b"catalog-data-1" in result, "Should contain first catalog data"
        assert b"catalog-data-2" in result, "Should contain second catalog data"

    def test_catalog_data_cached_on_second_call(self, tmp_path: Path) -> None:
        """_get_catalog_data returns cached data without re-reading."""
        cat_dir = (
            tmp_path
            / "Windows"
            / "System32"
            / "CatRoot"
            / "{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"
        )
        cat_dir.mkdir(parents=True)
        (cat_dir / "cached.cat").write_bytes(b"cached-data")

        fs = FilesystemHelper(image_root=tmp_path)
        extractor = SignerExtractor(fs)

        first_call = extractor._get_catalog_data()
        # Remove the file to prove caching
        (cat_dir / "cached.cat").unlink()
        second_call = extractor._get_catalog_data()

        assert first_call is second_call, (
            "Second call should return same cached list object"
        )
        assert len(second_call) == 1, "Cached data should still have original entry"


class TestCatalogLookup:
    """Tests for catalog-based signer lookup."""

    def test_lookup_in_catalogs_returns_empty_without_signify_ctl(
        self, tmp_path: Path
    ) -> None:
        """_lookup_in_catalogs returns '' when signify_ctl is not available."""
        fs = FilesystemHelper(image_root=tmp_path)
        extractor = SignerExtractor(fs)

        mock_pe = MagicMock()
        with patch("pyrsistencesniper.core.resolver._HAS_SIGNIFY_CTL", False):
            result = extractor._lookup_in_catalogs(mock_pe)
        assert result == "", "Should return empty string when signify_ctl unavailable"
