"""Tests for AppInitDlls multi-value parsing plugin."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1546.appinit_dlls import AppInitDlls

from .conftest import make_node, make_plugin


class TestAppInitDlls:
    """AppInitDlls parses multi-value DLL paths and LoadAppInit_DLLs context."""

    def test_happy_path_multiple_dlls(self, tmp_path: Path) -> None:
        """AppInit_DLLs with multiple DLL paths produces multiple findings."""
        node = make_node(
            values={
                "AppInit_DLLs": "C:\\evil.dll C:\\bad.dll",
                "LoadAppInit_DLLs": 1,
                "RequireSignedAppInit_DLLs": 0,
            }
        )
        p = make_plugin(AppInitDlls, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.side_effect = [node, None]  # native + wow64

        findings = p.run()
        assert len(findings) == 2
        assert any("evil.dll" in f.value for f in findings)
        assert any("bad.dll" in f.value for f in findings)
        assert any("LoadAppInit_DLLs=1" in f.value for f in findings)
        assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)

    def test_load_appinit_disabled(self, tmp_path: Path) -> None:
        """LoadAppInit_DLLs=0 still reports but marks INACTIVE in context."""
        node = make_node(
            values={
                "AppInit_DLLs": "C:\\sneaky.dll",
                "LoadAppInit_DLLs": 0,
            }
        )
        p = make_plugin(AppInitDlls, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.side_effect = [node, None]

        findings = p.run()
        assert len(findings) == 1
        assert "INACTIVE" in findings[0].value

    def test_empty_appinit_value(self, tmp_path: Path) -> None:
        """Empty AppInit_DLLs string produces no findings."""
        node = make_node(values={"AppInit_DLLs": ""})
        p = make_plugin(AppInitDlls, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.side_effect = [node, None]

        assert p.run() == []
