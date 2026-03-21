from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.active_setup import ActiveSetup

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_stubpath_child_produces_finding(tmp_path: Path) -> None:
    child = make_node(name="{comp}", values={"StubPath": "C:\\evil\\setup.exe"})
    tree = make_node(children={"{comp}": child})
    plugin = make_plugin(ActiveSetup, tmp_path)
    setup_hklm(plugin, tree)
    findings = plugin.run()
    assert len(findings) == 1
    f = findings[0]
    assert "setup.exe" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
    assert "T1547" in f.mitre_id


def test_stub_flag_values_skipped(tmp_path: Path) -> None:
    child = make_node(name="{flag}", values={"StubPath": "/UserInstall"})
    tree = make_node(children={"{flag}": child})
    plugin = make_plugin(ActiveSetup, tmp_path)
    setup_hklm(plugin, tree)
    assert plugin.run() == []


def test_missing_stubpath_skipped(tmp_path: Path) -> None:
    child = make_node(name="{empty}", values={"Version": "1,0,0,0"})
    tree = make_node(children={"{empty}": child})
    plugin = make_plugin(ActiveSetup, tmp_path)
    setup_hklm(plugin, tree)
    assert plugin.run() == []
