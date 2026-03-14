"""Tests for all 8 debugger hijacking plugins (7 declarative + 1 custom)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1546.debugger_hijacking import (
    AeDebug,
    AeDebugProtected,
    DotNetDbgManagedDebugger,
    LsmDebugger,
    WerDebugger,
    WerHangs,
    WerReflectDebugger,
    WerRuntimeExceptionHelperModules,
)

from .conftest import make_node, make_plugin, setup_hklm


class TestAeDebug:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"Debugger": "evil.exe"})
        p = make_plugin(AeDebug, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node
        findings = p.run()
        assert len(findings) == 1
        assert "evil.exe" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM


class TestAeDebugProtected:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"Debugger": "backdoor.exe"})
        p = make_plugin(AeDebugProtected, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node
        findings = p.run()
        assert len(findings) == 1
        assert "backdoor.exe" in findings[0].value


class TestWerDebugger:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"Debugger": "wer_evil.exe"})
        p = make_plugin(WerDebugger, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node
        findings = p.run()
        assert len(findings) == 1
        assert "wer_evil.exe" in findings[0].value


class TestWerReflectDebugger:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"ReflectDebugger": "reflect_evil.exe"})
        p = make_plugin(WerReflectDebugger, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node
        findings = p.run()
        assert len(findings) == 1
        assert "reflect_evil.exe" in findings[0].value


class TestWerHangs:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"Debugger": "hang_evil.exe"})
        p = make_plugin(WerHangs, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node
        findings = p.run()
        assert len(findings) == 1
        assert "hang_evil.exe" in findings[0].value


class TestDotNetDbgManagedDebugger:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"DbgManagedDebugger": "dotnet_evil.exe"})
        p = make_plugin(DotNetDbgManagedDebugger, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node
        findings = p.run()
        assert len(findings) >= 1
        assert any("dotnet_evil.exe" in f.value for f in findings)


class TestLsmDebugger:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"MonitorProcess": "lsm_evil.exe"})
        p = make_plugin(LsmDebugger, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node
        findings = p.run()
        assert len(findings) == 1
        assert "lsm_evil.exe" in findings[0].value


class TestWerRuntimeExceptionHelperModules:
    def test_happy_path(self, tmp_path: Path) -> None:
        """RuntimeExceptionHelperModules DLL path produces a finding."""
        tree = make_node(values={"C:\\evil\\helper.dll": 0})
        p = make_plugin(WerRuntimeExceptionHelperModules, tmp_path)
        setup_hklm(p, tree)
        findings = p.run()
        assert len(findings) == 1
        assert "helper.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_empty_value_name_skipped(self, tmp_path: Path) -> None:
        """Value with blank name is skipped."""
        tree = make_node(values={"  ": 0, "C:\\real.dll": 1})
        p = make_plugin(WerRuntimeExceptionHelperModules, tmp_path)
        setup_hklm(p, tree)
        findings = p.run()
        assert len(findings) == 1
        assert "real.dll" in findings[0].value
