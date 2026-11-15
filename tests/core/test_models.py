"""Tests for Finding, FilterRule matching, and time-evidence descriptors."""

from __future__ import annotations

import pytest
from pyrsistencesniper.core.models import (
    EventLogTime,
    FileWriteTime,
    FilterRule,
    Finding,
    MatchResult,
)


def test_finding_defaults() -> None:
    """Tri-state fields default to None (unresolved), never False."""
    finding = Finding()
    assert finding.is_lolbin is None
    assert finding.exists is None
    assert finding.is_builtin is None


def test_finding_is_frozen() -> None:
    """A produced finding cannot be edited later by resolution or output code."""
    finding = Finding(path="HKLM\\Software\\Run")
    with pytest.raises(AttributeError):
        finding.path = "something"  # type: ignore[misc]


def test_change_columns_follow_severity() -> None:
    """Reports place change time beside severity, so column order is a contract."""
    keys = list(Finding.FIELDS)
    assert keys[keys.index("severity") + 1 : keys.index("severity") + 3] == [
        "last_change",
        "change_source",
    ]
    assert Finding.FIELDS["last_change"] == "Last Change"
    assert Finding.FIELDS["change_source"] == "Change Source"


def test_finding_change_defaults_are_empty() -> None:
    """Unenriched findings carry blanks and empty tuples, never None."""
    finding = Finding()
    assert finding.last_change == ""
    assert finding.change_source == ""
    assert finding.time_evidence == ()
    assert finding.change_candidates == ()


def test_time_evidence_descriptors_are_frozen() -> None:
    """Evidence timestamps stay as captured; no later stage can rewrite them."""
    with pytest.raises(AttributeError):
        FileWriteTime(path="a").path = "x"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        EventLogTime(channel="System").channel = "x"  # type: ignore[misc]


def test_allow_rule_empty_matches_nothing() -> None:
    """An unconfigured rule suppresses nothing rather than allowlisting everything."""
    rule = FilterRule()
    finding = Finding(value="anything", path="anywhere")
    assert rule.matches(finding) is False


def test_allow_rule_value_equals() -> None:
    """Anchored patterns match case-insensitively, since Windows casing varies."""
    rule = FilterRule(value_matches=r"^explorer\.exe$")
    assert rule.matches(Finding(value="explorer.exe")) is True
    assert rule.matches(Finding(value="EXPLORER.EXE")) is True
    assert rule.matches(Finding(value="notepad.exe")) is False


def test_allow_rule_value_contains() -> None:
    """Unanchored patterns search anywhere in the value, keeping SysWOW64 distinct."""
    rule = FilterRule(value_matches=r"system32")
    assert rule.matches(Finding(value="C:\\Windows\\system32\\foo.exe")) is True
    assert rule.matches(Finding(value="C:\\Windows\\SysWOW64\\foo.exe")) is False


def test_allow_rule_path_equals() -> None:
    """Anchoring keeps a Run rule from also allowlisting RunOnce."""
    rule = FilterRule(path_matches=r"^HKLM\\Software\\Run$")
    assert rule.matches(Finding(path="HKLM\\Software\\Run")) is True
    assert rule.matches(Finding(path="hklm\\software\\run")) is True
    assert rule.matches(Finding(path="HKLM\\Software\\RunOnce")) is False


def test_allow_rule_path_contains() -> None:
    """Without anchors one rule covers a family of keys: Run and RunOnce alike."""
    rule = FilterRule(path_matches=r"Run")
    assert rule.matches(Finding(path="HKLM\\Software\\Run")) is True
    assert rule.matches(Finding(path="HKLM\\Software\\RunOnce")) is True
    assert rule.matches(Finding(path="HKLM\\Software\\Services")) is False


def test_allow_rule_signer_match() -> None:
    """Signer text is compared case-insensitively, as certificate casing varies."""
    rule = FilterRule(signer="Microsoft Corporation")
    assert rule.matches(Finding(signer="Microsoft Corporation")) is True
    assert rule.matches(Finding(signer="microsoft corporation")) is True


def test_allow_rule_signer_fail_open_when_empty() -> None:
    """An unresolved signature is not credited as the trusted signer."""
    rule = FilterRule(signer="Microsoft Corporation")
    assert rule.matches(Finding(signer="")) is False


def test_allow_rule_hash_match() -> None:
    """Hash comparison ignores case, since tools emit hex in both."""
    rule = FilterRule(hash="abc123")
    assert rule.matches(Finding(sha256="ABC123")) is True
    assert rule.matches(Finding(sha256="def456")) is False


def test_allow_rule_and_logic_all_must_match() -> None:
    """Conditions are ANDed, so a broad path rule cannot allowlist on its own."""
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


def test_match_result_full_when_all_conditions_match() -> None:
    """A rule with every condition satisfied is a clean hit, not a partial one."""
    rule = FilterRule(value_matches=r"^explorer\.exe$", path_matches=r"Winlogon")
    finding = Finding(value="explorer.exe", path="HKLM\\Winlogon")
    assert rule.match_result(finding) == MatchResult.FULL


def test_match_result_partial_when_core_passes_signer_fails() -> None:
    """PARTIAL marks a near-miss so an unverifiable signature stays visible."""
    rule = FilterRule(value_matches=r"^explorer\.exe$", signer="Unknown")
    finding = Finding(value="explorer.exe", signer="")
    assert rule.match_result(finding) == MatchResult.PARTIAL


def test_match_result_none_when_core_fails() -> None:
    """One failed core condition sinks the whole rule; there is no partial credit."""
    rule = FilterRule(value_matches=r"^explorer\.exe$", path_matches=r"Winlogon")
    finding = Finding(value="explorer.exe", path="HKLM\\Run")
    assert rule.match_result(finding) == MatchResult.NONE


def test_match_result_none_when_no_conditions_match() -> None:
    """An unrelated finding never reaches PARTIAL and is not surfaced at all."""
    rule = FilterRule(value_matches=r"^explorer\.exe$", path_matches=r"Winlogon")
    finding = Finding(value="notepad.exe", path="HKLM\\Run")
    assert rule.match_result(finding) == MatchResult.NONE


def test_match_result_none_for_empty_rule() -> None:
    """An empty rule scores NONE, so a blank config suppresses nothing."""
    rule = FilterRule()
    finding = Finding(value="anything", path="anywhere")
    assert rule.match_result(finding) == MatchResult.NONE


def test_match_result_none_when_core_fails_signer_matches() -> None:
    """A matching signer cannot promote a failed path condition to a near-miss."""
    rule = FilterRule(path_matches=r"Winlogon", signer="Microsoft")
    finding = Finding(path="HKLM\\Run", signer="Microsoft Windows")
    assert rule.match_result(finding) == MatchResult.NONE


def test_match_result_none_when_only_signer_fails() -> None:
    """A sole signer condition that fails is a plain miss, never a near-miss."""
    rule = FilterRule(signer="Unknown")
    finding = Finding(signer="Microsoft Windows")
    assert rule.match_result(finding) == MatchResult.NONE


def test_match_result_full_when_only_signer_matches() -> None:
    """A signer-only rule can reach FULL on its own, without a value or path test."""
    rule = FilterRule(signer="Microsoft")
    finding = Finding(signer="Microsoft Windows")
    assert rule.match_result(finding) == MatchResult.FULL


_MS_RULE = FilterRule(signer="Microsoft", not_lolbin=True)


def test_signed_microsoft_not_lolbin_suppressed() -> None:
    """The default Microsoft rule suppresses the ordinary signed OS binary noise."""
    finding = Finding(
        value="svchost.exe",
        signer="Microsoft Windows",
        is_lolbin=False,
        is_in_os_directory=True,
    )
    assert _MS_RULE.matches(finding) is True


def test_unsigned_not_in_os_dir_not_suppressed() -> None:
    """An unsigned binary under a user profile survives the Microsoft signer rule."""
    finding = Finding(
        value=r"C:\Users\test\malware.exe",
        signer="",
        is_lolbin=False,
        is_in_os_directory=False,
    )
    assert _MS_RULE.matches(finding) is False


def test_lolbin_signed_microsoft_in_system32_not_suppressed() -> None:
    """A LOLBin escapes the Microsoft rule however well signed it is."""
    finding = Finding(
        value="powershell.exe",
        signer="Microsoft Windows",
        is_lolbin=True,
        is_in_os_directory=True,
    )
    assert _MS_RULE.matches(finding) is False


def test_lolbin_in_os_dir_not_suppressed() -> None:
    """An OS-directory LOLBin is exactly what the signer rule must not hide."""
    finding = Finding(
        value="mshta.exe",
        signer="",
        is_lolbin=True,
        is_in_os_directory=True,
    )
    assert _MS_RULE.matches(finding) is False


def test_signer_case_insensitive() -> None:
    """Certificate subjects arrive in mixed case and must still match the rule."""
    finding = Finding(
        value="test.dll",
        signer="MICROSOFT CORPORATION",
        is_lolbin=False,
        is_in_os_directory=False,
    )
    assert _MS_RULE.matches(finding) is True


def test_signer_substring_microsoft_windows() -> None:
    """A Microsoft rule matches by substring, so the Windows subject is covered."""
    finding = Finding(value="test.dll", signer="Microsoft Windows", is_lolbin=False)
    assert _MS_RULE.matches(finding) is True


def test_signer_substring_microsoft_corporation() -> None:
    """One Microsoft rule spares maintaining a rule per subject line."""
    finding = Finding(value="test.dll", signer="Microsoft Corporation", is_lolbin=False)
    assert _MS_RULE.matches(finding) is True


def test_signer_substring_microsoft_windows_publisher() -> None:
    """Extra trailing words in the subject do not break the substring match."""
    finding = Finding(
        value="test.dll", signer="Microsoft Windows Publisher", is_lolbin=False
    )
    assert _MS_RULE.matches(finding) is True


def test_none_is_lolbin_not_suppressed() -> None:
    """An unresolved LOLBin flag is not credited as proof the binary is not one."""
    finding = Finding(
        value="unknown.exe",
        signer="Microsoft Windows",
        is_lolbin=None,
        is_in_os_directory=True,
    )
    assert _MS_RULE.matches(finding) is False


def test_value_and_signer_both_match() -> None:
    """A rule may pin both what runs and who signed it, and both must hold."""
    rule = FilterRule(value_matches=r"explorer\.exe", signer="Microsoft")
    finding = Finding(value="explorer.exe", signer="Microsoft Windows")
    assert rule.matches(finding) is True


def test_value_match_but_unsigned_no_match() -> None:
    """A right-named binary with no signature is not the allowlisted one."""
    rule = FilterRule(value_matches=r"explorer\.exe", signer="Microsoft")
    finding = Finding(value="explorer.exe", signer="")
    assert rule.matches(finding) is False


def test_value_match_but_wrong_signer_no_match() -> None:
    """Naming a binary explorer.exe does not inherit the Microsoft allowlist entry."""
    rule = FilterRule(value_matches=r"explorer\.exe", signer="Microsoft")
    finding = Finding(value="explorer.exe", signer="Evil Corp")
    assert rule.matches(finding) is False
