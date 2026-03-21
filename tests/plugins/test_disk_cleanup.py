"""Tests for DiskCleanupHandler CLSID enumeration + InprocServer32 resolution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.disk_cleanup import DiskCleanupHandler

from .conftest import make_node, make_plugin


class TestDiskCleanupHandler:
    """DiskCleanupHandler enumerates VolumeCaches handlers and resolves CLSIDs."""

    def test_happy_path_handler_with_inproc(self, tmp_path: Path) -> None:
        """Handler with CLSID and InprocServer32 DLL produces a finding."""
        handler_node = make_node(name="OldFiles", values={"(Default)": "{CLSID-1}"})
        tree = make_node(children={"OldFiles": handler_node})
        inproc_node = make_node(
            name="InprocServer32",
            values={"(Default)": "C:\\evil.dll"},
        )

        p = make_plugin(DiskCleanupHandler, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.side_effect = [tree, inproc_node]

        findings = p.run()
        assert len(findings) == 1
        assert "evil.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_handler_without_inproc_resolution(self, tmp_path: Path) -> None:
        """Handler exists but InprocServer32 not found -- no finding."""
        handler_node = make_node(name="Broken", values={"(Default)": "{CLSID-X}"})
        tree = make_node(children={"Broken": handler_node})

        p = make_plugin(DiskCleanupHandler, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.side_effect = [tree, None]  # InprocServer32 not found

        assert p.run() == []

    def test_handler_without_clsid(self, tmp_path: Path) -> None:
        """Handler with non-CLSID (Default) value is skipped."""
        handler_node = make_node(name="NoClsid", values={"(Default)": "not-a-clsid"})
        tree = make_node(children={"NoClsid": handler_node})

        p = make_plugin(DiskCleanupHandler, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.return_value = tree

        assert p.run() == []
