from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.models.finding import Finding

# -- default profile ----------------------------------------------------------


def test_default_profile_no_rules() -> None:
    profile = DetectionProfile.default()
    assert profile.allow == ()
    assert profile.block == ()
    assert profile.checks == {}


def test_default_profile_all_enabled() -> None:
    profile = DetectionProfile.default()
    assert profile.is_enabled("any_check_id") is True


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
    assert profile.is_enabled("noisy_check") is False
    assert profile.is_enabled("other_check") is True


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


# -- matches_allow ------------------------------------------------------------


def test_matches_allow_global_rule(tmp_path: Path) -> None:
    yaml_content = """\
allow:
  - value_matches: "^explorer\\\\.exe$"
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)

    finding = Finding(value="explorer.exe")
    assert profile.matches_allow("any_check", finding) is True


def test_matches_allow_per_check_rule(tmp_path: Path) -> None:
    yaml_content = """\
checks:
  my_check:
    allow:
      - value_matches: "safe"
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)

    finding = Finding(value="safe_app.exe")
    assert profile.matches_allow("my_check", finding) is True
    assert profile.matches_allow("other_check", finding) is False


# -- matches_block ------------------------------------------------------------


def test_matches_block_global_rule(tmp_path: Path) -> None:
    yaml_content = """\
block:
  - path_matches: "Temp"
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)

    finding = Finding(path="C:\\Users\\Temp\\evil.exe")
    assert profile.matches_block("any_check", finding) is True


def test_matches_block_no_match(tmp_path: Path) -> None:
    yaml_content = """\
block:
  - path_matches: "Temp"
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)

    finding = Finding(path="C:\\Windows\\System32\\cmd.exe")
    assert profile.matches_block("any_check", finding) is False


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


def test_default_profile_has_trusted_signers() -> None:
    profile = DetectionProfile.default()
    assert "microsoft windows" in profile.trusted_signers
    assert "microsoft corporation" in profile.trusted_signers


def test_load_custom_trusted_signers(tmp_path: Path) -> None:
    yaml_content = """\
trusted_signers:
  - "My Organization"
  - "Another Vendor"
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)
    assert profile.trusted_signers == frozenset({"my organization", "another vendor"})
    assert "microsoft windows" not in profile.trusted_signers


def test_load_no_trusted_signers_uses_defaults(tmp_path: Path) -> None:
    yaml_content = """\
allow:
  - reason: "test"
    value_matches: "test"
"""
    p = tmp_path / "profile.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    profile = DetectionProfile.load(p)
    assert "microsoft windows" in profile.trusted_signers


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
