"""Tests for the resolution pipeline that fills file metadata on findings."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, create_autospec, patch

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.models import Finding
from pyrsistencesniper.core.resolver import ResolutionPipeline


def _make_pipeline(
    exists: bool = False,
    sha256: str = "",
) -> ResolutionPipeline:
    """Build a pipeline over a stub filesystem with fixed exists and sha256 answers."""
    filesystem = create_autospec(FilesystemHelper, instance=True)
    filesystem.exists.return_value = exists
    filesystem.sha256.return_value = sha256
    filesystem.resolve.side_effect = lambda windows_path: Path("/fake") / windows_path
    return ResolutionPipeline(filesystem)


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_lolbin(_mock_signer: MagicMock) -> None:
    """A bare LOLBin name is classified without the file needing to exist."""
    pipeline = _make_pipeline()
    finding = Finding(value="mshta.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_builtin(_mock_signer: MagicMock) -> None:
    """Classification of a built-in comes from the name, not from disk."""
    pipeline = _make_pipeline()
    finding = Finding(value="explorer.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_builtin is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_non_lolbin_non_builtin(_mock_signer: MagicMock) -> None:
    """An unknown binary comes back decided as False, not left unknown."""
    pipeline = _make_pipeline()
    finding = Finding(value="custom_app.exe")
    assert finding.is_lolbin is None
    assert finding.is_builtin is None
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is False
    assert resolved.is_builtin is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_caches_by_path(_mock_signer: MagicMock) -> None:
    """Two Run keys naming one binary get the same verdict out of the cache."""
    pipeline = _make_pipeline()
    from_run = pipeline.resolve(Finding(value="mshta.exe", path="HKLM\\Run"))
    from_run_once = pipeline.resolve(Finding(value="mshta.exe", path="HKLM\\RunOnce"))
    assert from_run.is_lolbin == from_run_once.is_lolbin is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_none_fields(_mock_signer: MagicMock) -> None:
    """Unset tri-state fields are decided here rather than left unknown."""
    pipeline = _make_pipeline(exists=True)
    finding = Finding(value="mshta.exe")
    assert finding.is_lolbin is None
    assert finding.is_builtin is None
    assert finding.exists is None
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is True
    assert resolved.is_builtin is False
    assert resolved.exists is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_exists_true(_mock_signer: MagicMock) -> None:
    """A present file is recorded as present rather than left unknown."""
    pipeline = _make_pipeline(exists=True)
    finding = Finding(value="notepad.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.exists is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_exists_false(_mock_signer: MagicMock) -> None:
    """A path-like value the helper cannot find is a definite absence, not a gap."""
    pipeline = _make_pipeline(exists=False)
    finding = Finding(value="notepad.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.exists is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_sha256(_mock_signer: MagicMock) -> None:
    """The hash reaches the finding, which is what makes a report checkable."""
    pipeline = _make_pipeline(exists=True, sha256="abc123def456")
    finding = Finding(value="notepad.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.sha256 == "abc123def456"


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_extracts_executable_from_cmdline(_mock_signer: MagicMock) -> None:
    """For cmd /c malware.exe the resolver extracts malware.exe, not cmd."""
    pipeline = _make_pipeline()
    finding = Finding(value="cmd /c malware.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_lolbin is False
    assert resolved.is_builtin is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_case_insensitive_cache(_mock_signer: MagicMock) -> None:
    """cmd.exe and CMD.EXE share one metadata entry, so hashing runs only once."""
    pipeline = _make_pipeline(exists=True, sha256="abc123")
    pipeline.resolve(Finding(value="cmd.exe", path="HKLM\\Run"))
    pipeline.resolve(Finding(value="CMD.EXE", path="HKLM\\RunOnce"))
    assert pipeline._fs.sha256.call_count == 1


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_skips_sha256_when_not_exists(_mock_signer: MagicMock) -> None:
    """A file that is not there is never hashed, so no digest is invented."""
    pipeline = _make_pipeline(exists=False)
    finding = Finding(value="missing.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.exists is False
    assert resolved.sha256 == ""
    pipeline._fs.sha256.assert_not_called()


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_in_os_directory_true(_mock_signer: MagicMock) -> None:
    """System32 residency is derived from the value alone, with no disk access."""
    pipeline = _make_pipeline()
    finding = Finding(value="C:\\Windows\\System32\\svchost.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_in_os_directory_false(_mock_signer: MagicMock) -> None:
    """A user-profile binary is marked outside the OS directories."""
    pipeline = _make_pipeline()
    finding = Finding(value="C:\\Users\\test\\malware.exe")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_fills_is_in_os_directory_subdirectory(_mock_signer: MagicMock) -> None:
    """A driver under System32\\drivers is inside the OS tree, not merely near it."""
    pipeline = _make_pipeline()
    finding = Finding(value="C:\\Windows\\System32\\drivers\\srv.sys")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_bare_dll_fallback_to_system32(_mock_signer: MagicMock) -> None:
    """A bare DLL name is looked for in System32, where the loader would find it."""
    filesystem = create_autospec(FilesystemHelper, instance=True)
    filesystem.exists.side_effect = lambda windows_path: (
        windows_path == "Windows\\System32\\ifmon.dll"
    )
    filesystem.sha256.return_value = ""
    filesystem.resolve.side_effect = lambda windows_path: Path("/fake") / windows_path
    pipeline = ResolutionPipeline(filesystem)
    finding = Finding(value="ifmon.dll")
    resolved = pipeline.resolve(finding)
    assert resolved.is_in_os_directory is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_leaves_existence_unknown_for_clsid(_mock_signer: MagicMock) -> None:
    """A CLSID value is not a path, so the scan must not claim it is missing."""
    pipeline = _make_pipeline(exists=False)
    finding = Finding(value="{B2A052B6-0EF7-40C8-AE36-C46284541FED}")
    assert pipeline.resolve(finding).exists is None


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_leaves_existence_unknown_for_bare_package_name(
    _mock_signer: MagicMock,
) -> None:
    """A package name with no extension is not a path, so existence stays unknown."""
    pipeline = _make_pipeline(exists=False)
    assert pipeline.resolve(Finding(value="msv1_0")).exists is None


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_reports_missing_file_for_absolute_path(
    _mock_signer: MagicMock,
) -> None:
    """An absolute path that is absent is a real, reportable negative."""
    pipeline = _make_pipeline(exists=False)
    assert pipeline.resolve(Finding(value=r"C:\temp\evil.exe")).exists is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_reports_missing_file_for_bare_filename(
    _mock_signer: MagicMock,
) -> None:
    """A bare filename with an extension is still looked for on disk."""
    pipeline = _make_pipeline(exists=False)
    assert pipeline.resolve(Finding(value="ifmon.dll")).exists is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_uses_resolve_target_when_set(
    _mock_signer: MagicMock, tmp_path: Path
) -> None:
    """A plugin that flags the artifact itself names it via resolve_target."""
    target = tmp_path / "ProgramData" / "Startup" / "evil.lnk"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"MZ")
    pipeline = ResolutionPipeline(FilesystemHelper(image_root=tmp_path))

    finding = Finding(
        path="ProgramData\\Startup\\evil.lnk",
        value="evil.lnk",
        resolve_target="ProgramData\\Startup\\evil.lnk",
    )
    resolved = pipeline.resolve(finding)
    assert resolved.exists is True
    assert resolved.sha256


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_never_hashes_the_artifact_for_cmdline_values(
    _mock_signer: MagicMock, tmp_path: Path
) -> None:
    """A missing referenced binary is a NOT_FOUND, not a hash of the task XML."""
    artifact = tmp_path / "Windows" / "System32" / "Tasks" / "EvilTask"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("<Task/>")
    pipeline = ResolutionPipeline(FilesystemHelper(image_root=tmp_path))

    finding = Finding(
        path="Windows\\System32\\Tasks\\EvilTask",
        value=r"C:\Program Files\evil\evil.exe --run",
    )
    resolved = pipeline.resolve(finding)
    assert resolved.exists is False
    assert resolved.sha256 == ""


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_leaves_marker_values_unresolved(
    _mock_signer: MagicMock, tmp_path: Path
) -> None:
    """A non-path marker value stays unresolved even when the artifact exists."""
    artifact = (
        tmp_path / "Windows" / "System32" / "wbem" / "Repository" / "OBJECTS.DATA"
    )
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"CIM")
    pipeline = ResolutionPipeline(FilesystemHelper(image_root=tmp_path))

    finding = Finding(
        path="Windows\\System32\\wbem\\Repository\\OBJECTS.DATA",
        value="CommandLineEventConsumer (class reference)",
    )
    resolved = pipeline.resolve(finding)
    assert resolved.exists is None
    assert resolved.sha256 == ""


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_finds_bare_name_in_windows_dir(
    _mock_signer: MagicMock, tmp_path: Path
) -> None:
    """A bare filename living beside the OS binaries is still found and hashed."""
    target = tmp_path / "Windows" / "explorer.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"MZ")
    pipeline = ResolutionPipeline(FilesystemHelper(image_root=tmp_path))

    finding = Finding(path="HKLM\\SOFTWARE\\Winlogon\\Shell", value="explorer.exe")
    assert pipeline.resolve(finding).exists is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_flags_lolbin_launcher_of_a_plain_payload(
    _mock_signer: MagicMock,
) -> None:
    """Adding an argument must not make a finding less suspicious than the bare tool."""
    pipeline = _make_pipeline()
    resolved = pipeline.resolve(
        Finding(value=r"rundll32.exe C:\Users\Public\evil.dll,Start")
    )
    assert resolved.is_lolbin is True
    assert resolved.launcher == "rundll32.exe"


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_flags_powershell_launcher(_mock_signer: MagicMock) -> None:
    """PowerShell is absent from LOLBAS but is the commonest launcher in the wild."""
    pipeline = _make_pipeline()
    resolved = pipeline.resolve(
        Finding(value=r"powershell.exe -w hidden -File C:\Users\Public\evil.ps1")
    )
    assert resolved.is_lolbin is True
    assert resolved.launcher == "powershell.exe"


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_still_inspects_the_payload_not_the_launcher(
    _mock_signer: MagicMock,
) -> None:
    """The launcher is recorded, but the payload is what gets hashed and signed."""
    pipeline = _make_pipeline(exists=True, sha256="abc123")
    resolved = pipeline.resolve(
        Finding(value=r"rundll32.exe C:\Users\Public\evil.dll,Start")
    )
    assert resolved.sha256 == "abc123"
    assert resolved.exists is True


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_records_no_launcher_for_a_direct_image(
    _mock_signer: MagicMock,
) -> None:
    """An ordinary program is not proxying, so the launcher column stays empty."""
    pipeline = _make_pipeline()
    resolved = pipeline.resolve(Finding(value=r"C:\Program Files\App\app.exe --flag"))
    assert resolved.launcher == ""
    assert resolved.is_lolbin is False


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_leaves_no_triage_note_for_an_unresolved_value(
    _mock_signer: MagicMock,
) -> None:
    """A value that names no file gives the analyst nothing to triage."""
    resolved = _make_pipeline().resolve(Finding(value="{00000000-0000-0000-0000-0000}"))
    assert resolved.triage_notes == ""


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_notes_a_missing_binary_without_signature_claims(
    _mock_signer: MagicMock,
) -> None:
    """An absent binary is flagged as missing, never also as unsigned."""
    resolved = _make_pipeline(exists=False).resolve(Finding(value="C:\\Temp\\gone.exe"))
    assert "not found" in resolved.triage_notes
    assert "signature" not in resolved.triage_notes


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_notes_an_unsigned_binary_outside_the_os(
    _mock_signer: MagicMock,
) -> None:
    """A present binary with no signer, outside the OS directories, earns both notes."""
    resolved = _make_pipeline(exists=True).resolve(Finding(value="C:\\Temp\\evil.exe"))
    assert "no usable signature" in resolved.triage_notes
    assert "outside the OS directories" in resolved.triage_notes


@patch(
    "pyrsistencesniper.core.signer.SignerExtractor.extract",
    return_value="Microsoft Windows",
)
def test_resolve_stays_quiet_for_a_signed_os_binary(_mock_signer: MagicMock) -> None:
    """A signed binary in System32 that is no LOLBin needs no triage note."""
    resolved = _make_pipeline(exists=True).resolve(
        Finding(value="C:\\Windows\\System32\\spoolsv.exe")
    )
    assert resolved.triage_notes == ""


@patch("pyrsistencesniper.core.signer.SignerExtractor.extract", return_value="")
def test_resolve_notes_a_lolbin(_mock_signer: MagicMock) -> None:
    """A living off the land binary is called out by name of the technique."""
    resolved = _make_pipeline().resolve(Finding(value="mshta.exe"))
    assert "living off the land" in resolved.triage_notes
