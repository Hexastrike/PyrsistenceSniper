"""Tests for the GpScripts filesystem plugin (T1037.001)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1037.gp_scripts import GpScripts

from .conftest import make_plugin

if TYPE_CHECKING:
    from pathlib import Path


def _gp_base(tmp_path: Path) -> Path:
    """Return the GroupPolicy directory root, creating it."""
    gp = tmp_path / "Windows" / "System32" / "GroupPolicy"
    gp.mkdir(parents=True, exist_ok=True)
    return gp


def test_detects_machine_startup_script(tmp_path: Path) -> None:
    """Happy path: Machine scripts.ini with a CmdLine entry is detected."""
    gp = _gp_base(tmp_path)
    scripts_dir = gp / "Machine" / "Scripts"
    scripts_dir.mkdir(parents=True)
    ini = scripts_dir / "scripts.ini"
    ini.write_text(
        "[Startup]\n0CmdLine=C:\\evil.bat\n0Parameters=-silent\n",
        encoding="utf-8",
    )

    plugin = make_plugin(GpScripts, tmp_path)
    findings = plugin.run()

    assert len(findings) == 1
    finding = findings[0]
    assert "evil.bat" in finding.value
    assert "-silent" in finding.value
    assert finding.access_gained == AccessLevel.SYSTEM
    assert finding.mitre_id == "T1037.001"
    assert "Machine" in finding.path


def test_detects_user_logon_script(tmp_path: Path) -> None:
    """Happy path: User scripts.ini CmdLine entry detected with USER access."""
    gp = _gp_base(tmp_path)
    scripts_dir = gp / "User" / "Scripts"
    scripts_dir.mkdir(parents=True)
    ini = scripts_dir / "scripts.ini"
    ini.write_text("[Logon]\n0CmdLine=payload.exe\n", encoding="utf-8")

    plugin = make_plugin(GpScripts, tmp_path)
    findings = plugin.run()

    assert len(findings) == 1
    finding = findings[0]
    assert "payload.exe" in finding.value
    assert finding.access_gained == AccessLevel.USER


def test_non_utf8_encoding(tmp_path: Path) -> None:
    """Edge case: UTF-16 encoded INI file is parsed correctly."""
    gp = _gp_base(tmp_path)
    scripts_dir = gp / "Machine" / "Scripts"
    scripts_dir.mkdir(parents=True)
    ini = scripts_dir / "scripts.ini"
    ini.write_text("[Startup]\n0CmdLine=encoded.exe\n", encoding="utf-16")

    plugin = make_plugin(GpScripts, tmp_path)
    findings = plugin.run()

    assert len(findings) == 1
    assert "encoded.exe" in findings[0].value


def test_empty_cmdline_ignored(tmp_path: Path) -> None:
    """Edge case: CmdLine with blank value is skipped."""
    gp = _gp_base(tmp_path)
    scripts_dir = gp / "Machine" / "Scripts"
    scripts_dir.mkdir(parents=True)
    ini = scripts_dir / "scripts.ini"
    ini.write_text("[Startup]\n0CmdLine=   \n", encoding="utf-8")

    plugin = make_plugin(GpScripts, tmp_path)
    assert plugin.run() == []
