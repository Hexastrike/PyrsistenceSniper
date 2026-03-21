from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.print_monitors import (
    PrintMonitors,
    PrintProcessors,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


class TestPrintMonitors:
    def test_happy_path(self, tmp_path: Path) -> None:
        child = make_node(name="EvilMon", values={"Driver": "evil_mon.dll"})
        tree = make_node(children={"EvilMon": child})
        p = make_plugin(PrintMonitors, tmp_path)
        setup_hklm(p, tree, hive_path="/fake/SYSTEM")
        findings = p.run()
        assert len(findings) == 1
        assert "evil_mon.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert "T1547.010" in findings[0].mitre_id

    def test_missing_driver_skipped(self, tmp_path: Path) -> None:
        child = make_node(name="SomeMon", values={"Other": "data"})
        tree = make_node(children={"SomeMon": child})
        p = make_plugin(PrintMonitors, tmp_path)
        setup_hklm(p, tree, hive_path="/fake/SYSTEM")
        assert p.run() == []

    def test_no_subtree(self, tmp_path: Path) -> None:
        p = make_plugin(PrintMonitors, tmp_path)
        p.context.hive_path.return_value = None
        assert p.run() == []

    def test_multiple_monitors(self, tmp_path: Path) -> None:
        child_a = make_node(name="MonA", values={"Driver": "a.dll"})
        child_b = make_node(name="MonB", values={"Driver": "b.dll"})
        tree = make_node(children={"MonA": child_a, "MonB": child_b})
        p = make_plugin(PrintMonitors, tmp_path)
        setup_hklm(p, tree, hive_path="/fake/SYSTEM")
        findings = p.run()
        assert len(findings) == 2


class TestPrintProcessors:
    def test_happy_path(self, tmp_path: Path) -> None:
        child = make_node(name="EvilProc", values={"Driver": "evil_proc.dll"})
        tree = make_node(children={"EvilProc": child})
        p = make_plugin(PrintProcessors, tmp_path)
        setup_hklm(p, tree, hive_path="/fake/SYSTEM")
        findings = p.run()
        assert len(findings) >= 1
        assert any("evil_proc.dll" in f.value for f in findings)
        assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)

    def test_missing_driver_skipped(self, tmp_path: Path) -> None:
        child = make_node(name="SomeProc", values={"Other": "data"})
        tree = make_node(children={"SomeProc": child})
        p = make_plugin(PrintProcessors, tmp_path)
        setup_hklm(p, tree, hive_path="/fake/SYSTEM")
        assert p.run() == []

    def test_no_subtree(self, tmp_path: Path) -> None:
        p = make_plugin(PrintProcessors, tmp_path)
        p.context.hive_path.return_value = None
        assert p.run() == []
