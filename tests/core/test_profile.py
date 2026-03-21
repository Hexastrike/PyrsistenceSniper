from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from pyrsistencesniper.core.models import FilterRule
from pyrsistencesniper.core.profile import DetectionProfile

# -- default profile ----------------------------------------------------------


def test_default_profile_no_rules() -> None:
    profile = DetectionProfile()
    assert profile.allow == ()
    assert profile.block == ()
    assert profile.checks == {}


# -- effective_rules -----------------------------------------------------------


def test_effective_rules_unknown_check_returns_globals() -> None:
    profile = DetectionProfile(
        allow=(FilterRule(value_matches="global"),),
        block=(FilterRule(path_matches="Temp"),),
    )
    rules = profile.effective_rules("unknown_check")
    assert rules.allow == (FilterRule(value_matches="global"),)
    assert rules.block == (FilterRule(path_matches="Temp"),)
    assert rules.enabled is True


def test_effective_rules_merges_global_and_check_rules() -> None:
    from pyrsistencesniper.core.profile import CheckOverride

    profile = DetectionProfile(
        allow=(FilterRule(value_matches="global_allow"),),
        block=(FilterRule(path_matches="global_block"),),
        checks={
            "my_check": CheckOverride(
                allow=(FilterRule(value_matches="check_allow"),),
                block=(FilterRule(path_matches="check_block"),),
            )
        },
    )
    rules = profile.effective_rules("my_check")
    assert len(rules.allow) == 2
    assert rules.allow[0].value_matches == "global_allow"
    assert rules.allow[1].value_matches == "check_allow"
    assert len(rules.block) == 2
    assert rules.block[0].path_matches == "global_block"
    assert rules.block[1].path_matches == "check_block"


def test_effective_rules_disabled_check() -> None:
    from pyrsistencesniper.core.profile import CheckOverride

    profile = DetectionProfile(
        checks={"noisy": CheckOverride(enabled=False)},
    )
    assert profile.effective_rules("noisy").enabled is False


def test_effective_rules_unknown_check_enabled_by_default() -> None:
    profile = DetectionProfile()
    assert profile.effective_rules("any_check_id").enabled is True


# -- load from YAML -----------------------------------------------------------


def test_load_global_allow(tmp_path: Path) -> None:
    yaml_content = """\
allow:
  - reason: "Known good"
    value_matches: "^explorer\\\\.exe$"
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)
    assert len(profile.allow) == 1
    assert profile.allow[0].value_matches == "^explorer\\.exe$"
    assert profile.allow[0].reason == "Known good"


def test_load_global_block(tmp_path: Path) -> None:
    yaml_content = """\
block:
  - reason: "Suspicious"
    path_matches: "Temp"
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)
    assert len(profile.block) == 1
    assert profile.block[0].path_matches == "Temp"


def test_load_check_override_disabled(tmp_path: Path) -> None:
    yaml_content = """\
checks:
  noisy_check:
    enabled: false
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)
    assert profile.effective_rules("noisy_check").enabled is False
    assert profile.effective_rules("other_check").enabled is True


def test_load_check_override_with_allow(tmp_path: Path) -> None:
    yaml_content = """\
checks:
  my_check:
    allow:
      - value_matches: "safe"
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)
    assert len(profile.checks["my_check"].allow) == 1


def test_load_invalid_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "profile.yaml"
    p.write_text("not: [valid: yaml: {{{", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to parse"):
        DetectionProfile.load(p)


def test_load_nonexistent_returns_default(tmp_path: Path) -> None:
    profile = DetectionProfile.load(tmp_path / "missing.yaml")
    assert profile.allow == ()


# -- error handling ----------------------------------------------------------


def test_load_non_dict_yaml_raises(tmp_path: Path) -> None:
    """A YAML file that parses to a list (not dict) should raise."""
    p = tmp_path / "profile.yaml"
    p.write_text("- item1\n- item2\n", encoding="utf-8")
    with pytest.raises(TypeError, match="must be a YAML mapping"):
        DetectionProfile.load(p)


def test_load_empty_yaml_raises(tmp_path: Path) -> None:
    """An empty YAML file parses to None, which is not a dict."""
    p = tmp_path / "profile.yaml"
    p.write_text("", encoding="utf-8")
    with pytest.raises(TypeError, match="must be a YAML mapping"):
        DetectionProfile.load(p)


def test_load_checks_as_list_no_crash(tmp_path: Path) -> None:
    """A YAML file with checks as a list (not dict) should not crash."""
    yaml_content = """\
checks:
  - item1
  - item2
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)
    assert profile.checks == {}
