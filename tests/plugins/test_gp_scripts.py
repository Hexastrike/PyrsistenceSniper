"""Tests for the GpScripts filesystem plugin (T1037.001)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.core.registry import artifact_failures
from pyrsistencesniper.plugins.T1037.gp_scripts import GpScripts

from .conftest import make_plugin

if TYPE_CHECKING:
    from pathlib import Path


def _gp_base(tmp_path: Path) -> Path:
    """Return the GroupPolicy directory root, creating it."""
    group_policy_root = tmp_path / "Windows" / "System32" / "GroupPolicy"
    group_policy_root.mkdir(parents=True, exist_ok=True)
    return group_policy_root


def _write_ini(directory: Path, name: str, content: bytes) -> None:
    """Write raw INI bytes into a directory, creating it first."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(content)


def _write_machine_ini(tmp_path: Path, content: bytes) -> None:
    """Write the machine scripts.ini the startup-script scanner reads."""
    _write_ini(_gp_base(tmp_path) / "Machine" / "Scripts", "scripts.ini", content)


def test_detects_machine_startup_script(tmp_path: Path) -> None:
    """A machine startup CmdLine runs as SYSTEM before any user logs on."""
    _write_machine_ini(
        tmp_path, b"[Startup]\n0CmdLine=C:\\evil.bat\n0Parameters=-silent\n"
    )

    findings = make_plugin(GpScripts, tmp_path).run()

    assert len(findings) == 1
    finding = findings[0]
    assert "evil.bat" in finding.value
    assert "-silent" in finding.value
    assert finding.access_gained == AccessLevel.SYSTEM
    assert finding.mitre_id == "T1037.001"
    assert "Machine" in finding.path


def test_detects_user_logon_script(tmp_path: Path) -> None:
    """A user logon CmdLine runs as that user at every logon."""
    _write_ini(
        _gp_base(tmp_path) / "User" / "Scripts",
        "scripts.ini",
        b"[Logon]\n0CmdLine=payload.exe\n",
    )

    findings = make_plugin(GpScripts, tmp_path).run()

    assert len(findings) == 1
    assert "payload.exe" in findings[0].value
    assert findings[0].access_gained == AccessLevel.USER


def test_non_utf8_encoding(tmp_path: Path) -> None:
    """gpedit writes these files as UTF-16, so UTF-8-only reading would miss them."""
    _write_machine_ini(tmp_path, "[Startup]\n0CmdLine=encoded.exe\n".encode("utf-16"))

    findings = make_plugin(GpScripts, tmp_path).run()

    assert len(findings) == 1
    assert "encoded.exe" in findings[0].value


def test_ansi_encoded_file_is_read(tmp_path: Path) -> None:
    """A cp1252 script path is still a script path, not a file to discard whole."""
    _write_machine_ini(
        tmp_path,
        "[Startup]\n0CmdLine=C:\\Skripte\\aufr\xe4umen.cmd\n".encode("cp1252"),
    )

    findings = make_plugin(GpScripts, tmp_path).run()

    assert len(findings) == 1
    assert "aufr\xe4umen.cmd" in findings[0].value


def test_empty_cmdline_ignored(tmp_path: Path) -> None:
    """A CmdLine holding only whitespace runs nothing and is not persistence."""
    _write_machine_ini(tmp_path, b"[Startup]\n0CmdLine=   \n")

    assert make_plugin(GpScripts, tmp_path).run() == []


def test_per_user_local_gpo_logon_script_detected(tmp_path: Path) -> None:
    """A Multiple Local GPO logon script under GroupPolicyUsers is persistence."""
    account_sid = "S-1-5-21-1111-2222-3333-1001"
    _write_ini(
        tmp_path
        / "Windows"
        / "System32"
        / "GroupPolicyUsers"
        / account_sid
        / "User"
        / "Scripts",
        "psscripts.ini",
        b"[Logon]\r\n0CmdLine=C:\\Users\\Public\\bd.ps1\r\n0Parameters=-w hidden\r\n",
    )

    findings = make_plugin(GpScripts, tmp_path).run()

    assert len(findings) == 1
    finding = findings[0]
    assert "bd.ps1" in finding.value
    assert "-w hidden" in finding.value
    assert finding.access_gained == AccessLevel.USER
    assert finding.path == (
        f"Windows\\System32\\GroupPolicyUsers\\{account_sid}"
        "\\User\\Scripts\\psscripts.ini"
    )
    assert account_sid in finding.description


def test_empty_group_policy_users_directory_stays_quiet(tmp_path: Path) -> None:
    """The live-host layout: the directories exist, no INI file does, nothing fires."""
    (tmp_path / "Windows" / "System32" / "GroupPolicyUsers").mkdir(parents=True)
    (tmp_path / "Windows" / "System32" / "GroupPolicy" / "Machine" / "Scripts").mkdir(
        parents=True
    )

    assert make_plugin(GpScripts, tmp_path).run() == []
    assert artifact_failures() == ()


def test_malformed_line_keeps_the_entries_it_could_read(tmp_path: Path) -> None:
    """A line with no delimiter costs its own line, never the rest of the file."""
    _write_machine_ini(
        tmp_path,
        (
            "[Startup]\r\n0CmdLine=C:\\ProgramData\\evil.exe\r\n"
            "0Parameters=\r\nrem keep\r\n"
        ).encode("utf-16"),
    )

    findings = make_plugin(GpScripts, tmp_path).run()

    assert len(findings) == 1
    assert "evil.exe" in findings[0].value


def test_malformed_line_is_reported_as_lost_coverage(tmp_path: Path) -> None:
    """The line that would not parse is named in the report, not swallowed at DEBUG."""
    _write_machine_ini(
        tmp_path,
        b"[Startup]\r\n0CmdLine=C:\\ProgramData\\evil.exe\r\nrem keep\r\n",
    )

    make_plugin(GpScripts, tmp_path).run()

    (failure,) = artifact_failures()
    assert failure.check_id == "gp_scripts"
    assert "scripts.ini" in failure.artifact
    assert failure.error == "no key=value pair could be read from line(s) 3"


def test_well_formed_file_reports_no_lost_coverage(tmp_path: Path) -> None:
    """A clean INI file, comments and blank lines included, raises no integrity flag."""
    _write_machine_ini(
        tmp_path,
        b"; generated by gpedit\r\n\r\n[Startup]\r\n0CmdLine=C:\\evil.bat\r\n",
    )

    findings = make_plugin(GpScripts, tmp_path).run()

    assert len(findings) == 1
    assert artifact_failures() == ()


def test_duplicate_keys_and_sections_are_kept(tmp_path: Path) -> None:
    """Duplicates a strict parser rejects outright must not cost the whole file."""
    _write_machine_ini(
        tmp_path,
        b"[Startup]\r\n0CmdLine=first.exe\r\n0CmdLine=second.exe\r\n"
        b"[Startup]\r\n1CmdLine=third.exe\r\n",
    )

    findings = make_plugin(GpScripts, tmp_path).run()

    assert [finding.value for finding in findings] == [
        "first.exe",
        "second.exe",
        "third.exe",
    ]
