"""Tests for AmsiProviders CLSID enumeration plugin."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1546.amsi_providers import AmsiProviders

from .conftest import make_node, make_plugin


class TestAmsiProviders:
    """AmsiProviders enumerates AMSI provider CLSIDs and resolves InprocServer32."""

    def test_happy_path_provider_with_inproc(self, tmp_path: Path) -> None:
        """AMSI provider CLSID with InprocServer32 DLL produces a finding."""
        clsid_child = make_node(name="{AAAA-BBBB}")
        tree = make_node(children={"{AAAA-BBBB}": clsid_child})
        p = make_plugin(AmsiProviders, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        inproc_node = make_node(values={"(Default)": "C:\\evil_amsi.dll"})
        p.registry.load_subtree.side_effect = [tree, inproc_node]

        findings = p.run()
        assert len(findings) == 1
        assert "evil_amsi.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert "AMSI" in findings[0].path

    def test_provider_without_inproc_resolution(self, tmp_path: Path) -> None:
        """Provider CLSID exists but InprocServer32 resolution returns empty."""
        clsid_child = make_node(name="{NO-INPROC}")
        tree = make_node(children={"{NO-INPROC}": clsid_child})
        p = make_plugin(AmsiProviders, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        # tree loads OK, but InprocServer32 subtree is None
        p.registry.load_subtree.side_effect = [tree, None]

        findings = p.run()
        assert findings == []
