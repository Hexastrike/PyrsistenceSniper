from __future__ import annotations

import struct
from pathlib import Path

from pyrsistencesniper.models.finding import AccessLevel

from .conftest import make_node, make_plugin, setup_hklm


def _make_f_value(rid: int) -> bytes:
    """Build a minimal SAM F-value with *rid* at offset 0x30."""
    return b"\x00" * 0x30 + struct.pack("<I", rid) + b"\x00" * 20


def test_rid_hijacking(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1098.rid_hijacking import RidHijacking

    child = make_node(name="000003E9", values={"F": _make_f_value(500)})
    tree = make_node(children={"000003E9": child})
    p = make_plugin(RidHijacking, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SAM")
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "mismatch" in f.value.lower()
    assert f.access_gained == AccessLevel.SYSTEM
    assert "T1098" in f.mitre_id


def test_rid_hijacking_no_mismatch(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1098.rid_hijacking import RidHijacking

    child = make_node(name="000001F4", values={"F": _make_f_value(500)})
    tree = make_node(children={"000001F4": child})
    p = make_plugin(RidHijacking, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SAM")
    assert p.run() == []


def test_rid_suborner(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1098.rid_hijacking import RidSuborner

    child = make_node(name="000003E9", values={"F": _make_f_value(500)})
    tree = make_node(children={"000003E9": child})
    p = make_plugin(RidSuborner, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SAM")
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "suborner" in f.value.lower()
    assert f.access_gained == AccessLevel.SYSTEM
