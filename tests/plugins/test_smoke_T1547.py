from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel

from .conftest import make_node, make_plugin, setup_hklm


def test_active_setup(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.active_setup import ActiveSetup

    child = make_node(name="{comp}", values={"StubPath": "C:\\evil\\setup.exe"})
    tree = make_node(children={"{comp}": child})
    p = make_plugin(ActiveSetup, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "setup.exe" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
    assert "T1547" in f.mitre_id


def test_explorer_context_menu(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.explorer_context_menu import (
        ExplorerContextMenu,
    )

    handler_node = make_node(name="EvilHandler", values={"(Default)": "{CLSID-X}"})
    tree = make_node(children={"EvilHandler": handler_node})

    p = make_plugin(ExplorerContextMenu, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.side_effect = [tree, None, None, None]

    findings = p.run()
    assert len(findings) == 1
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_explorer_bho(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.explorer_persistence import (
        ExplorerBrowserHelperObjects,
    )

    clsid_child = make_node(name="{BHO-CLSID}")
    tree = make_node(children={"{BHO-CLSID}": clsid_child})
    p = make_plugin(ExplorerBrowserHelperObjects, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    inproc_node = make_node(values={"(Default)": "C:\\bho.dll"})
    p.registry.load_subtree.side_effect = [tree, inproc_node]
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "bho.dll" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_explorer_app_key(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.explorer_persistence import (
        ExplorerAppKey,
    )

    child = make_node(name="18", values={"ShellExecute": "C:\\evil.exe"})
    tree = make_node(children={"18": child})
    p = make_plugin(ExplorerAppKey, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.exe" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_dsrm_backdoor(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.dsrm_backdoor import DsrmBackdoor

    node = make_node(values={"DsrmAdminLogonBehavior": 2})
    p = make_plugin(DsrmBackdoor, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SYSTEM")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.side_effect = [node, None, None]
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert f.value == "2"
    assert f.access_gained == AccessLevel.SYSTEM
    assert "T1547" in f.mitre_id
