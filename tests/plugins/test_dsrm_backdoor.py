from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1547.dsrm_backdoor import DsrmBackdoor

from .conftest import make_node, make_plugin


def test_dsrm_value_2_produces_finding(tmp_path: Path) -> None:
    node = make_node(values={"DsrmAdminLogonBehavior": 2})
    plugin = make_plugin(DsrmBackdoor, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    hive = MagicMock()
    plugin.registry.open_hive.return_value = hive
    plugin.registry.load_subtree.side_effect = [node, None, None]
    findings = plugin.run()
    assert len(findings) == 1
    f = findings[0]
    assert f.value == "2"
    assert f.access_gained == AccessLevel.SYSTEM
    assert "T1547" in f.mitre_id


def test_dsrm_value_not_2_returns_empty(tmp_path: Path) -> None:
    node = make_node(values={"DsrmAdminLogonBehavior": 0})
    plugin = make_plugin(DsrmBackdoor, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    hive = MagicMock()
    plugin.registry.open_hive.return_value = hive
    plugin.registry.load_subtree.side_effect = [node, None, None]
    assert plugin.run() == []
