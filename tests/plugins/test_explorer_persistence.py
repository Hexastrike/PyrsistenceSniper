from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.explorer_persistence import (
    ExplorerAppKey,
    ExplorerBrowserHelperObjects,
    ExplorerLoad,
)

from .conftest import make_node, make_plugin, setup_hklm


class TestBrowserHelperObjects:
    """Tests for ExplorerBrowserHelperObjects -- BHO CLSID resolution."""

    def test_bho_with_inprocserver32_resolved(self, tmp_path: Path) -> None:
        """BHO CLSID resolves to InprocServer32 DLL path."""
        clsid_child = make_node(name="{BHO-CLSID}")
        tree = make_node(children={"{BHO-CLSID}": clsid_child})
        inproc_node = make_node(values={"(Default)": r"C:\bho.dll"})

        p = make_plugin(ExplorerBrowserHelperObjects, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.side_effect = [tree, inproc_node]

        findings = p.run()
        assert len(findings) == 1
        assert "bho.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_bho_without_inprocserver32_shows_clsid(self, tmp_path: Path) -> None:
        """BHO CLSID without InprocServer32 still reports the CLSID."""
        clsid_child = make_node(name="{ORPHAN-BHO}")
        tree = make_node(children={"{ORPHAN-BHO}": clsid_child})

        p = make_plugin(ExplorerBrowserHelperObjects, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        # tree then None for CLSID resolution
        p.registry.load_subtree.side_effect = [tree, None]

        findings = p.run()
        assert len(findings) == 1
        assert "{ORPHAN-BHO}" in findings[0].value


class TestExplorerLoad:
    """Tests for ExplorerLoad -- declarative plugin."""

    def test_load_value_present(self, tmp_path: Path) -> None:
        """Happy path: Load value in registry produces finding."""
        node = make_node(values={"Load": r"C:\evil\payload.exe"})

        p = make_plugin(ExplorerLoad, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = node

        findings = p.run()
        assert len(findings) >= 1
        assert any("payload.exe" in f.value for f in findings)


class TestAppKeys:
    """Tests for ExplorerAppKey -- iterates AppKey children."""

    def test_app_key_with_shell_execute(self, tmp_path: Path) -> None:
        """AppKey child with ShellExecute value produces finding."""
        child = make_node(name="18", values={"ShellExecute": r"C:\evil.exe"})
        tree = make_node(children={"18": child})

        p = make_plugin(ExplorerAppKey, tmp_path)
        setup_hklm(p, tree)

        findings = p.run()
        assert len(findings) == 1
        assert "evil.exe" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_app_key_with_association(self, tmp_path: Path) -> None:
        """AppKey child with Association value produces finding."""
        child = make_node(name="7", values={"Association": "evilapp"})
        tree = make_node(children={"7": child})

        p = make_plugin(ExplorerAppKey, tmp_path)
        setup_hklm(p, tree)

        findings = p.run()
        assert len(findings) == 1
        assert "evilapp" in findings[0].value

    def test_app_key_with_both_values(self, tmp_path: Path) -> None:
        """AppKey child with both ShellExecute and Association produces two findings."""
        child = make_node(
            name="15",
            values={"ShellExecute": r"C:\app.exe", "Association": "myapp"},
        )
        tree = make_node(children={"15": child})

        p = make_plugin(ExplorerAppKey, tmp_path)
        setup_hklm(p, tree)

        findings = p.run()
        assert len(findings) == 2
