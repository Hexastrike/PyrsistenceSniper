from __future__ import annotations

import pytest
from pyrsistencesniper.core.models import (
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
    rule = FilterRule(value_matches=r"^explorer\.exe$", signer="Unknown")
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
    rule = FilterRule(path_matches=r"Winlogon", signer="Microsoft")
    f = Finding(path="HKLM\\Run", signer="Microsoft Windows")
    assert rule.match_result(f) == MatchResult.NONE


def test_match_result_none_when_only_signer_fails() -> None:
    rule = FilterRule(signer="Unknown")
    f = Finding(signer="Microsoft Windows")
    assert rule.match_result(f) == MatchResult.NONE


def test_match_result_full_when_only_signer_matches() -> None:
    rule = FilterRule(signer="Microsoft")
    f = Finding(signer="Microsoft Windows")
    assert rule.match_result(f) == MatchResult.FULL


# -- Suppression via FilterRule ------------------------------------------------
# The old _is_auto_suppressed function has been replaced by plugin-level
# FilterRule entries with signer= and not_lolbin= fields.  These tests verify
# that the same filtering behaviour is achieved through FilterRule.matches().

_MS_RULE = FilterRule(signer="Microsoft", not_lolbin=True)


# -- basic suppression logic --------------------------------------------------


def test_signed_microsoft_not_lolbin_suppressed() -> None:
    finding = Finding(
        value="svchost.exe",
        signer="Microsoft Windows",
        is_lolbin=False,
        is_in_os_directory=True,
    )
    assert _MS_RULE.matches(finding) is True


def test_unsigned_not_in_os_dir_not_suppressed() -> None:
    finding = Finding(
        value=r"C:\Users\test\malware.exe",
        signer="",
        is_lolbin=False,
        is_in_os_directory=False,
    )
    assert _MS_RULE.matches(finding) is False


# -- LOLBin exemption --------------------------------------------------------


def test_lolbin_signed_microsoft_in_system32_not_suppressed() -> None:
    """LOLBins are NOT suppressed, even when signed by MS."""
    finding = Finding(
        value="powershell.exe",
        signer="Microsoft Windows",
        is_lolbin=True,
        is_in_os_directory=True,
    )
    assert _MS_RULE.matches(finding) is False


def test_lolbin_in_os_dir_not_suppressed() -> None:
    finding = Finding(
        value="mshta.exe",
        signer="",
        is_lolbin=True,
        is_in_os_directory=True,
    )
    assert _MS_RULE.matches(finding) is False


# -- signer case insensitivity -----------------------------------------------


def test_signer_case_insensitive() -> None:
    finding = Finding(
        value="test.dll",
        signer="MICROSOFT CORPORATION",
        is_lolbin=False,
        is_in_os_directory=False,
    )
    assert _MS_RULE.matches(finding) is True


# -- signer substring matching -----------------------------------------------


def test_signer_substring_microsoft_windows() -> None:
    finding = Finding(value="test.dll", signer="Microsoft Windows", is_lolbin=False)
    assert _MS_RULE.matches(finding) is True


def test_signer_substring_microsoft_corporation() -> None:
    finding = Finding(value="test.dll", signer="Microsoft Corporation", is_lolbin=False)
    assert _MS_RULE.matches(finding) is True


def test_signer_substring_microsoft_windows_publisher() -> None:
    finding = Finding(
        value="test.dll", signer="Microsoft Windows Publisher", is_lolbin=False
    )
    assert _MS_RULE.matches(finding) is True


# -- None fields (unresolved) ------------------------------------------------


def test_none_is_lolbin_not_suppressed() -> None:
    """When is_lolbin is None (unresolved), not_lolbin rule doesn't match."""
    finding = Finding(
        value="unknown.exe",
        signer="Microsoft Windows",
        is_lolbin=None,
        is_in_os_directory=True,
    )
    assert _MS_RULE.matches(finding) is False


# -- value + signer combo (known defaults in plugins) ------------------------


def test_value_and_signer_both_match() -> None:
    rule = FilterRule(value_matches=r"explorer\.exe", signer="Microsoft")
    finding = Finding(value="explorer.exe", signer="Microsoft Windows")
    assert rule.matches(finding) is True


def test_value_match_but_unsigned_no_match() -> None:
    rule = FilterRule(value_matches=r"explorer\.exe", signer="Microsoft")
    finding = Finding(value="explorer.exe", signer="")
    assert rule.matches(finding) is False


def test_value_match_but_wrong_signer_no_match() -> None:
    rule = FilterRule(value_matches=r"explorer\.exe", signer="Microsoft")
    finding = Finding(value="explorer.exe", signer="Evil Corp")
    assert rule.matches(finding) is False
