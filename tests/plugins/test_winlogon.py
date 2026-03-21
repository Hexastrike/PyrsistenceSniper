from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.winlogon import (
    WinlogonMPNotify,
    WinlogonNotifyPackages,
    WinlogonShell,
    WinlogonUserinit,
)

from .conftest import make_node, make_plugin, setup_hklm


class TestWinlogonShell:
    """Tests for WinlogonShell -- declarative with FilterRule."""

    def test_non_default_shell_detected(self, tmp_path: Path) -> None:
        """Non-default Shell value produces a finding."""
        node = make_node(values={"Shell": r"C:\evil\shell.exe"})

        p = make_plugin(WinlogonShell, tmp_path)
        setup_hklm(p, node)

        findings = p.run()
        assert len(findings) >= 1
        assert any("shell.exe" in f.value for f in findings)
        assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)

    def test_explorer_exe_still_produces_finding(self, tmp_path: Path) -> None:
        """Default explorer.exe still produces a finding at plugin level.

        FilterRule filtering happens at pipeline level, not plugin level.
        """
        node = make_node(values={"Shell": "explorer.exe"})

        p = make_plugin(WinlogonShell, tmp_path)
        setup_hklm(p, node)

        findings = p.run()
        assert len(findings) >= 1
        assert any("explorer.exe" in f.value for f in findings)


class TestWinlogonUserinit:
    """Tests for WinlogonUserinit -- declarative with FilterRule."""

    def test_non_default_userinit_detected(self, tmp_path: Path) -> None:
        """Non-default Userinit value produces a finding."""
        node = make_node(values={"Userinit": r"C:\evil\init.exe,"})

        p = make_plugin(WinlogonUserinit, tmp_path)
        setup_hklm(p, node)

        findings = p.run()
        assert len(findings) >= 1
        assert any("init.exe" in f.value for f in findings)


class TestWinlogonMPNotify:
    """Tests for WinlogonMPNotify -- declarative, HKLM only."""

    def test_mpnotify_dll_detected(self, tmp_path: Path) -> None:
        """mpnotify value produces a finding."""
        node = make_node(values={"mpnotify": r"C:\evil\notify.dll"})

        p = make_plugin(WinlogonMPNotify, tmp_path)
        setup_hklm(p, node)

        findings = p.run()
        assert len(findings) == 1
        assert "notify.dll" in findings[0].value


class TestWinlogonNotifyPackages:
    """Tests for WinlogonNotifyPackages -- declarative with FilterRule."""

    def test_non_default_package_detected(self, tmp_path: Path) -> None:
        """Non-default Notification Packages value produces a finding."""
        node = make_node(values={"Notification Packages": "evilpkg"})

        p = make_plugin(WinlogonNotifyPackages, tmp_path)
        setup_hklm(p, node, hive_path="/fake/SYSTEM")

        findings = p.run()
        assert len(findings) == 1
        assert "evilpkg" in findings[0].value
