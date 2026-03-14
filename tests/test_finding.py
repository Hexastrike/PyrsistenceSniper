from __future__ import annotations

import pytest
from pyrsistencesniper.models.finding import (
    AccessLevel,
    FilterRule,
    Finding,
    MatchResult,
    Severity,
)

# -- Finding defaults ---------------------------------------------------------


def test_finding_defaults() -> None:
    f = Finding()
    assert f.path == ""
    assert f.value == ""
    assert f.technique == ""
    assert f.access_gained is AccessLevel.USER
    assert f.is_lolbin is None
    assert f.exists is None
    assert f.sha256 == ""
    assert f.is_builtin is None
    assert f.signer == ""
    assert f.hostname == ""
    assert f.check_id == ""
    assert f.severity is Severity.MEDIUM


def test_finding_is_frozen() -> None:
    f = Finding(path="HKLM\\Software\\Run")
    with pytest.raises(AttributeError):
        f.path = "something"  # type: ignore[misc]


# -- FilterRule.matches ---------------------------------------------------------


def test_allow_rule_empty_matches_nothing() -> None:
    rule = FilterRule()
    f = Finding(value="anything", path="anywhere")
    assert rule.matches(f) is False


def test_allow_rule_value_equals() -> None:
    rule = FilterRule(value_matches=r"^explorer\.exe$")
    assert rule.matches(Finding(value="explorer.exe")) is True
    assert rule.matches(Finding(value="EXPLORER.EXE")) is True
    assert rule.matches(Finding(value="notepad.exe")) is False


def test_allow_rule_value_contains() -> None:
    rule = FilterRule(value_matches=r"system32")
    assert rule.matches(Finding(value="C:\\Windows\\system32\\foo.exe")) is True
    assert rule.matches(Finding(value="C:\\Windows\\SysWOW64\\foo.exe")) is False


def test_allow_rule_path_equals() -> None:
    rule = FilterRule(path_matches=r"^HKLM\\Software\\Run$")
    assert rule.matches(Finding(path="HKLM\\Software\\Run")) is True
    assert rule.matches(Finding(path="hklm\\software\\run")) is True
    assert rule.matches(Finding(path="HKLM\\Software\\RunOnce")) is False


def test_allow_rule_path_contains() -> None:
    rule = FilterRule(path_matches=r"Run")
    assert rule.matches(Finding(path="HKLM\\Software\\Run")) is True
    assert rule.matches(Finding(path="HKLM\\Software\\RunOnce")) is True
    assert rule.matches(Finding(path="HKLM\\Software\\Services")) is False


def test_allow_rule_signer_match() -> None:
    rule = FilterRule(signer="Microsoft Corporation")
    assert rule.matches(Finding(signer="Microsoft Corporation")) is True
    assert rule.matches(Finding(signer="microsoft corporation")) is True


def test_allow_rule_signer_fail_open_when_empty() -> None:
    rule = FilterRule(signer="Microsoft Corporation")
    assert rule.matches(Finding(signer="")) is False


def test_allow_rule_hash_match() -> None:
    rule = FilterRule(hash="abc123")
    assert rule.matches(Finding(sha256="ABC123")) is True
    assert rule.matches(Finding(sha256="def456")) is False


def test_allow_rule_and_logic_all_must_match() -> None:
    rule = FilterRule(
        value_matches=r"^explorer\.exe$",
        path_matches=r"Winlogon",
    )
    both = Finding(value="explorer.exe", path="HKLM\\Winlogon")
    assert rule.matches(both) is True

    wrong_value = Finding(value="notepad.exe", path="HKLM\\Winlogon")
    assert rule.matches(wrong_value) is False

    wrong_path = Finding(value="explorer.exe", path="HKLM\\Run")
    assert rule.matches(wrong_path) is False


# -- FilterRule.match_result ---------------------------------------------------


def test_match_result_full_when_all_conditions_match() -> None:
    rule = FilterRule(value_matches=r"^explorer\.exe$", path_matches=r"Winlogon")
    f = Finding(value="explorer.exe", path="HKLM\\Winlogon")
    assert rule.match_result(f) == MatchResult.FULL


def test_match_result_partial_when_core_passes_signer_fails() -> None:
    rule = FilterRule(value_matches=r"^explorer\.exe$", signer="unknown")
    f = Finding(value="explorer.exe", signer="")
    assert rule.match_result(f) == MatchResult.PARTIAL


def test_match_result_none_when_core_fails() -> None:
    rule = FilterRule(value_matches=r"^explorer\.exe$", path_matches=r"Winlogon")
    f = Finding(value="explorer.exe", path="HKLM\\Run")
    assert rule.match_result(f) == MatchResult.NONE


def test_match_result_none_when_no_conditions_match() -> None:
    rule = FilterRule(value_matches=r"^explorer\.exe$", path_matches=r"Winlogon")
    f = Finding(value="notepad.exe", path="HKLM\\Run")
    assert rule.match_result(f) == MatchResult.NONE


def test_match_result_none_for_empty_rule() -> None:
    rule = FilterRule()
    f = Finding(value="anything", path="anywhere")
    assert rule.match_result(f) == MatchResult.NONE


def test_match_result_none_when_core_fails_signer_matches() -> None:
    rule = FilterRule(path_matches=r"Winlogon", signer="microsoft")
    f = Finding(path="HKLM\\Run", signer="Microsoft Windows")
    assert rule.match_result(f) == MatchResult.NONE


def test_match_result_none_when_only_signer_fails() -> None:
    rule = FilterRule(signer="unknown")
    f = Finding(signer="Microsoft Windows")
    assert rule.match_result(f) == MatchResult.NONE


def test_match_result_full_when_only_signer_matches() -> None:
    rule = FilterRule(signer="microsoft")
    f = Finding(signer="Microsoft Windows")
    assert rule.match_result(f) == MatchResult.FULL
