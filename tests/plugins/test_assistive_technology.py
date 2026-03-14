"""Tests for AssistiveTechnology multi-hive + CSV parsing plugin."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1546.assistive_technology import AssistiveTechnology

from .conftest import make_node, make_plugin, setup_hklm


class TestAssistiveTechnologyHKLM:
    """HKLM registry AT registration tests."""

    def test_happy_path_at_registration(self, tmp_path: Path) -> None:
        """AT with StartExe value produces a finding."""
        at_child = make_node(name="EvilAT", values={"StartExe": "C:\\evil\\at.exe"})
        tree = make_node(children={"EvilAT": at_child})
        p = make_plugin(AssistiveTechnology, tmp_path)
        setup_hklm(p, tree)

        findings = p.run()
        assert len(findings) >= 1
        assert any("at.exe" in f.value for f in findings)
        assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)

    def test_at_with_start_params(self, tmp_path: Path) -> None:
        """StartExe with StartParams appends params to value."""
        at_child = make_node(
            name="ParamAT",
            values={"StartExe": "C:\\tool.exe", "StartParams": "--evil"},
        )
        tree = make_node(children={"ParamAT": at_child})
        p = make_plugin(AssistiveTechnology, tmp_path)
        setup_hklm(p, tree)

        findings = p.run()
        # Both native and Wow64 AT paths return the same mock tree
        matching = [f for f in findings if "tool.exe" in f.value]
        assert len(matching) >= 1
        assert all("--evil" in f.value for f in matching)


class TestAssistiveTechnologyUserConfig:
    """HKU per-user Configuration CSV parsing tests."""

    def test_happy_path_user_config(self, tmp_path: Path) -> None:
        """User hive with Configuration CSV produces findings."""
        profiles = [
            UserProfile(
                username="victim",
                profile_path=Path("/Users/victim"),
                ntuser_path=Path("/Users/victim/NTUSER.DAT"),
            ),
        ]
        p = make_plugin(AssistiveTechnology, tmp_path, user_profiles=profiles)
        p.context.hive_path.return_value = None  # no HKLM hive
        ntuser = MagicMock()
        p.registry.open_hive.return_value = ntuser
        config_node = make_node(values={"Configuration": "EvilAT,CustomHelper"})
        p.registry.load_subtree.return_value = config_node

        findings = p.run()
        assert len(findings) == 2
        assert all(f.access_gained == AccessLevel.USER for f in findings)
        values = {f.value for f in findings}
        assert "EvilAT" in values
        assert "CustomHelper" in values

    def test_empty_configuration_value(self, tmp_path: Path) -> None:
        """Empty Configuration string produces no findings."""
        profiles = [
            UserProfile(
                username="user1",
                profile_path=Path("/Users/user1"),
                ntuser_path=Path("/Users/user1/NTUSER.DAT"),
            ),
        ]
        p = make_plugin(AssistiveTechnology, tmp_path, user_profiles=profiles)
        p.context.hive_path.return_value = None
        ntuser = MagicMock()
        p.registry.open_hive.return_value = ntuser
        config_node = make_node(values={"Configuration": ""})
        p.registry.load_subtree.return_value = config_node

        assert p.run() == []
