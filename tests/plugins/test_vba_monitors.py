"""Tests for VbaMonitors CLSID InprocServer32 lookup plugin."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1137.vba_monitors import VbaMonitors

from .conftest import make_node, make_plugin


def test_inprocserver32_value_produces_finding(tmp_path: Path) -> None:
    """CLSID with InprocServer32 default value produces SYSTEM finding."""
    inproc_node = make_node(values={"(Default)": "C:\\evil_vba.dll"})
    plugin = make_plugin(VbaMonitors, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    plugin.registry.open_hive.return_value = hive
    plugin.registry.load_subtree.return_value = inproc_node

    findings = plugin.run()

    assert len(findings) == 1
    f = findings[0]
    assert "evil_vba.dll" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
    assert "InprocServer32" in f.path


def test_clsid_exists_no_inproc_value_returns_empty(tmp_path: Path) -> None:
    """CLSID node exists but InprocServer32 has no default value."""
    empty_node = make_node(values={})
    plugin = make_plugin(VbaMonitors, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    plugin.registry.open_hive.return_value = hive
    plugin.registry.load_subtree.return_value = empty_node

    findings = plugin.run()
    assert findings == []
