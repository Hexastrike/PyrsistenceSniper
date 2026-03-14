"""Tests for RidHijacking and RidSuborner binary-parsing plugins (T1098)."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1098.rid_hijacking import RidHijacking, RidSuborner

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def _make_f_value(rid: int) -> bytes:
    """Build a minimal SAM F-value with *rid* at offset 0x30."""
    return b"\x00" * 0x30 + struct.pack("<I", rid) + b"\x00" * 20


class TestRidHijacking:
    """Tests for the RidHijacking plugin (general RID mismatch detection)."""

    def test_detects_rid_mismatch(self, tmp_path: Path) -> None:
        """Happy path: F-value RID (500) differs from subkey RID (0x3E9=1001)."""
        child = make_node(name="000003E9", values={"F": _make_f_value(500)})
        tree = make_node(children={"000003E9": child})
        plugin = make_plugin(RidHijacking, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SAM")

        findings = plugin.run()

        assert len(findings) == 1
        finding = findings[0]
        assert "mismatch" in finding.value.lower()
        assert "0x3E9" in finding.value
        assert "500" in finding.value
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "T1098" in finding.mitre_id
        assert "SAM" in finding.path

    def test_matching_rid_returns_empty(self, tmp_path: Path) -> None:
        """Unhappy: F-value RID matches subkey -- no hijacking."""
        child = make_node(name="000001F4", values={"F": _make_f_value(500)})
        tree = make_node(children={"000001F4": child})
        plugin = make_plugin(RidHijacking, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SAM")

        assert plugin.run() == []

    def test_f_value_too_short(self, tmp_path: Path) -> None:
        """Edge case: F-value shorter than 52 bytes is safely skipped."""
        short_f = b"\x00" * 20  # Way too short
        child = make_node(name="000003E9", values={"F": short_f})
        tree = make_node(children={"000003E9": child})
        plugin = make_plugin(RidHijacking, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SAM")

        assert plugin.run() == []

    def test_names_subkey_skipped(self, tmp_path: Path) -> None:
        """The 'Names' subkey is not a RID entry and must be skipped."""
        names_node = make_node(name="Names")
        child = make_node(name="000003E9", values={"F": _make_f_value(500)})
        tree = make_node(children={"Names": names_node, "000003E9": child})
        plugin = make_plugin(RidHijacking, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SAM")

        findings = plugin.run()
        assert len(findings) == 1  # Only the real RID entry, not Names

    def test_missing_f_value_skipped(self, tmp_path: Path) -> None:
        """Subkey without F value is silently skipped."""
        child = make_node(name="000003E9", values={})
        tree = make_node(children={"000003E9": child})
        plugin = make_plugin(RidHijacking, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SAM")

        assert plugin.run() == []


class TestRidSuborner:
    """Tests for the RidSuborner plugin (hidden admin account detection)."""

    def test_detects_suborner_account(self, tmp_path: Path) -> None:
        """Happy path: non-admin subkey (0x3E9) with F-value RID=500."""
        child = make_node(name="000003E9", values={"F": _make_f_value(500)})
        tree = make_node(children={"000003E9": child})
        plugin = make_plugin(RidSuborner, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SAM")

        findings = plugin.run()

        assert len(findings) == 1
        finding = findings[0]
        assert "suborner" in finding.value.lower()
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "T1098" in finding.mitre_id

    def test_actual_admin_not_flagged(self, tmp_path: Path) -> None:
        """Unhappy: real admin account (0x1F4=500) with RID=500 is not suborner."""
        child = make_node(name="000001F4", values={"F": _make_f_value(500)})
        tree = make_node(children={"000001F4": child})
        plugin = make_plugin(RidSuborner, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SAM")

        assert plugin.run() == []

    def test_non_admin_f_rid_not_flagged(self, tmp_path: Path) -> None:
        """Non-500 F-value RID is not a suborner even if RIDs differ."""
        child = make_node(name="000003E9", values={"F": _make_f_value(1001)})
        tree = make_node(children={"000003E9": child})
        plugin = make_plugin(RidSuborner, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SAM")

        assert plugin.run() == []

    def test_f_value_too_short(self, tmp_path: Path) -> None:
        """Edge case: short F-value is safely skipped."""
        child = make_node(name="000003E9", values={"F": b"\x00" * 10})
        tree = make_node(children={"000003E9": child})
        plugin = make_plugin(RidSuborner, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SAM")

        assert plugin.run() == []
