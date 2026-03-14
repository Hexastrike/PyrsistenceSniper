from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1547.explorer_context_menu import ExplorerContextMenu

from .conftest import make_node, make_plugin


class TestExplorerContextMenu:
    """Tests for ExplorerContextMenu CLSID resolution plugin."""

    def test_handler_with_clsid_resolved_to_dll(self, tmp_path: Path) -> None:
        """Happy path: handler (Default) is a CLSID, InprocServer32 resolves to DLL."""
        handler_node = make_node(
            name="EvilHandler", values={"(Default)": "{AAAA-BBBB}"}
        )
        tree = make_node(children={"EvilHandler": handler_node})
        inproc_node = make_node(values={"(Default)": r"C:\evil\shell_ext.dll"})

        p = make_plugin(ExplorerContextMenu, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        # 1st ctx path returns tree, CLSID resolution returns inproc,
        # other 2 ctx paths None
        p.registry.load_subtree.side_effect = [tree, inproc_node, None, None]

        findings = p.run()
        assert len(findings) == 1
        assert findings[0].value == r"C:\evil\shell_ext.dll"
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert "T1547" in findings[0].mitre_id

    def test_clsid_without_inprocserver32_skipped(self, tmp_path: Path) -> None:
        """Handler with CLSID but no InprocServer32 resolution still reports CLSID."""
        handler_node = make_node(name="Handler", values={"(Default)": "{NO-INPROC}"})
        tree = make_node(children={"Handler": handler_node})

        p = make_plugin(ExplorerContextMenu, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        # tree for first ctx path, None for other 2, None for CLSID resolution
        p.registry.load_subtree.side_effect = [tree, None, None, None]

        findings = p.run()
        assert len(findings) == 1
        assert "{NO-INPROC}" in findings[0].value

    def test_non_clsid_non_path_handler_skipped(self, tmp_path: Path) -> None:
        """Handler with plain name (not CLSID, not path) is skipped."""
        handler_node = make_node(
            name="PlainHandler", values={"(Default)": "SomePlainName"}
        )
        tree = make_node(children={"PlainHandler": handler_node})

        p = make_plugin(ExplorerContextMenu, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.side_effect = [tree, None, None]

        findings = p.run()
        assert findings == []

    def test_handler_with_path_value_reported(self, tmp_path: Path) -> None:
        """Handler whose (Default) is a direct file path is reported."""
        handler_node = make_node(
            name="PathHandler", values={"(Default)": r"C:\malware\handler.dll"}
        )
        tree = make_node(children={"PathHandler": handler_node})

        p = make_plugin(ExplorerContextMenu, tmp_path)
        p.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        p.registry.open_hive.return_value = hive
        p.registry.load_subtree.side_effect = [tree, None, None]

        findings = p.run()
        assert len(findings) == 1
        assert r"handler.dll" in findings[0].value
