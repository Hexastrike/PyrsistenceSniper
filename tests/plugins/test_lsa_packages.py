from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import Finding, MatchResult
from pyrsistencesniper.plugins.T1547.lsa_packages import (
    AuthenticationPackages,
    LsaCfgFlags,
    LsaRunAsPPL,
    SecurityPackages,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SYSTEM_HIVE = "/fake/SYSTEM"


def test_authentication_packages_happy(tmp_path: Path) -> None:
    node = make_node(values={"Authentication Packages": "evil_pkg"})
    plugin = make_plugin(AuthenticationPackages, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert "evil_pkg" in findings[0].value


def test_security_packages_happy(tmp_path: Path) -> None:
    node = make_node(values={"Security Packages": "evil_ssp"})
    plugin = make_plugin(SecurityPackages, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert "evil_ssp" in findings[0].value


def test_lsa_run_as_ppl_happy(tmp_path: Path) -> None:
    node = make_node(values={"RunAsPPL": "0"})
    plugin = make_plugin(LsaRunAsPPL, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) == 1
    assert "0" in findings[0].value


def test_lsa_run_as_ppl_empty(tmp_path: Path) -> None:
    node = make_node()
    plugin = make_plugin(LsaRunAsPPL, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    assert plugin.run() == []


def test_lsa_cfg_flags_happy(tmp_path: Path) -> None:
    node = make_node(values={"LsaCfgFlags": "0"})
    plugin = make_plugin(LsaCfgFlags, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) == 1
    assert "0" in findings[0].value


def test_lsa_cfg_flags_empty(tmp_path: Path) -> None:
    node = make_node()
    plugin = make_plugin(LsaCfgFlags, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    assert plugin.run() == []


class TestLsaRunAsPPLFilterRule:
    """Tests for the widened RunAsPPL pattern (allow[0])."""

    rule = LsaRunAsPPL.definition.allow[0]

    def test_value_1_matches(self) -> None:
        assert self.rule.match_result(Finding(value="1")) == MatchResult.FULL

    def test_value_2_matches(self) -> None:
        assert self.rule.match_result(Finding(value="2")) == MatchResult.FULL

    def test_value_0_no_match(self) -> None:
        assert self.rule.match_result(Finding(value="0")) == MatchResult.NONE

    def test_value_12_no_match(self) -> None:
        assert self.rule.match_result(Finding(value="12")) == MatchResult.NONE
