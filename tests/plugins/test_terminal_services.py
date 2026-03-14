from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1547.terminal_services import (
    RdpClxDll,
    RdpVirtualChannel,
    RdpWdsStartupPrograms,
    TsInitialProgram,
)

from .conftest import make_node, make_plugin


class TestTsInitialProgram:
    """Tests for TsInitialProgram -- declarative, multiple targets."""

    def test_initial_program_value_detected(self, tmp_path: Path) -> None:
        """InitialProgram value present produces a finding."""
        node = make_node(values={"InitialProgram": r"C:\backdoor.exe"})

        p = make_plugin(TsInitialProgram, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node

        findings = p.run()
        assert any("backdoor.exe" in f.value for f in findings)
        assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)


class TestRdpWdsStartupPrograms:
    """Tests for RdpWdsStartupPrograms -- declarative with FilterRule."""

    def test_non_default_startup_program(self, tmp_path: Path) -> None:
        """Non-default value produces a finding."""
        node = make_node(values={"StartupPrograms": "evil_clip"})

        p = make_plugin(RdpWdsStartupPrograms, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SYSTEM")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node

        findings = p.run()
        assert len(findings) == 1
        assert "evil_clip" in findings[0].value


class TestRdpClxDll:
    """Tests for RdpClxDll -- declarative."""

    def test_clx_dll_path_detected(self, tmp_path: Path) -> None:
        """ClxDllPath value produces a finding."""
        node = make_node(values={"ClxDllPath": r"C:\evil\clx.dll"})

        p = make_plugin(RdpClxDll, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SYSTEM")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node

        findings = p.run()
        assert len(findings) == 1
        assert "clx.dll" in findings[0].value


class TestRdpVirtualChannel:
    """Tests for RdpVirtualChannel -- custom run(), iterates addins."""

    def test_virtual_channel_dll_detected(self, tmp_path: Path) -> None:
        """Addin with DLL value produces a finding."""
        addin_node = make_node(name="MyAddin", values={"Name": r"C:\vc.dll"})
        tree = make_node(children={"MyAddin": addin_node})

        p = make_plugin(RdpVirtualChannel, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = tree

        findings = p.run()
        assert len(findings) == 1
        assert r"C:\vc.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_empty_addin_value_skipped(self, tmp_path: Path) -> None:
        """Addin with empty value is skipped."""
        addin_node = make_node(name="EmptyAddin", values={"Name": ""})
        tree = make_node(children={"EmptyAddin": addin_node})

        p = make_plugin(RdpVirtualChannel, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = tree

        assert p.run() == []
