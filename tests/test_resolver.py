from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.resolver import ResolutionPipeline
from pyrsistencesniper.models.finding import Finding


def _make_pipeline(
    exists: bool = False,
    sha256: str = "",
) -> ResolutionPipeline:
    fs = MagicMock(spec=FilesystemHelper)
    fs.exists.return_value = exists
    fs.sha256.return_value = sha256
    fs.resolve.side_effect = lambda p: Path("/fake") / p
    return ResolutionPipeline(fs)


# -- resolve fills fields -----------------------------------------------------


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_lolbin(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="mshta.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_builtin(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="explorer.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_builtin is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_non_lolbin_non_builtin(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="custom_app.exe")
    assert finding.is_lolbin is None
    assert finding.is_builtin is None
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is False
    assert resolved.is_builtin is False


# -- caching ------------------------------------------------------------------


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_caches_by_path(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    f1 = Finding(value="mshta.exe", path="HKLM\\Run")
    f2 = Finding(value="mshta.exe", path="HKLM\\RunOnce")
    r1 = pipeline.resolve(f1)
    r2 = pipeline.resolve(f2)
    assert r1.is_lolbin == r2.is_lolbin is True


# -- skip already set ---------------------------------------------------------


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_skips_already_set_fields(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="explorer.exe", is_builtin=True, is_lolbin=True)
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is True
    assert resolved.is_builtin is True


# -- tri-state logic ----------------------------------------------------------


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_respects_explicit_false_exists(_mock_signer: MagicMock) -> None:
    """A plugin that explicitly sets exists=False should not be overwritten."""
    pipeline = _make_pipeline(exists=True)
    finding = Finding(value="explorer.exe", exists=False)
    resolved = pipeline.resolve(finding)
    assert resolved.exists is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_respects_explicit_false_is_lolbin(_mock_signer: MagicMock) -> None:
    """A plugin that explicitly sets is_lolbin=False should not be overwritten."""
    pipeline = _make_pipeline()
    finding = Finding(value="mshta.exe", is_lolbin=False)
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_respects_explicit_false_is_builtin(_mock_signer: MagicMock) -> None:
    """A plugin that explicitly sets is_builtin=False should not be overwritten."""
    pipeline = _make_pipeline()
    finding = Finding(value="explorer.exe", is_builtin=False)
    resolved = pipeline.resolve(finding)
    assert resolved.is_builtin is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
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


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_exists_true(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline(exists=True)
    finding = Finding(value="notepad.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.exists is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_exists_false(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline(exists=False)
    finding = Finding(value="notepad.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.exists is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_sha256(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline(exists=True, sha256="abc123def456")
    finding = Finding(value="notepad.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.sha256 == "abc123def456"


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_extracts_executable_from_cmdline(_mock_signer: MagicMock) -> None:
    """cmd /c malware.exe — the resolver should extract malware.exe, not cmd."""
    pipeline = _make_pipeline()
    finding = Finding(value="cmd /c malware.exe")
    resolved = pipeline.resolve(finding)
    # cmd.exe is a lolbin and builtin; malware.exe is neither
    assert resolved.is_lolbin is False
    assert resolved.is_builtin is False


# -- case-insensitive cache ---------------------------------------------------


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
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


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
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


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_in_os_directory_true(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="C:\\Windows\\System32\\svchost.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_in_os_directory_false(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="C:\\Users\\test\\malware.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_in_os_directory_subdirectory(_mock_signer: MagicMock) -> None:
    pipeline = _make_pipeline()
    finding = Finding(value="C:\\Windows\\System32\\drivers\\srv.sys")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_bare_dll_fallback_to_system32(_mock_signer: MagicMock) -> None:
    """Bare DLL names like ifmon.dll should resolve to System32."""
    fs = MagicMock(spec=FilesystemHelper)
    # First call: bare name check, second: System32 path exists
    fs.exists.side_effect = lambda p: p == "Windows\\System32\\ifmon.dll"
    fs.sha256.return_value = ""
    fs.resolve.side_effect = lambda p: Path("/fake") / p
    pipeline = ResolutionPipeline(fs)
    finding = Finding(value="ifmon.dll")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is True
