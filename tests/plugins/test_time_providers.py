from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.time_providers import TimeProviders

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    child = make_node(name="EvilTP", values={"DllName": r"C:\evil_time.dll"})
    tree = make_node(children={"EvilTP": child})
    p = make_plugin(TimeProviders, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1
    assert "evil_time.dll" in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert "T1547.003" in findings[0].mitre_id


def test_missing_dllname_skipped(tmp_path: Path) -> None:
    child = make_node(name="NtpClient", values={"Enabled": 1})
    tree = make_node(children={"NtpClient": child})
    p = make_plugin(TimeProviders, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    assert p.run() == []


def test_empty_subtree(tmp_path: Path) -> None:
    tree = make_node()
    p = make_plugin(TimeProviders, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    assert p.run() == []


def test_multiple_providers(tmp_path: Path) -> None:
    child_a = make_node(name="ProvA", values={"DllName": "a.dll"})
    child_b = make_node(name="ProvB", values={"DllName": "b.dll"})
    tree = make_node(children={"ProvA": child_a, "ProvB": child_b})
    p = make_plugin(TimeProviders, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    assert len(p.run()) == 2
