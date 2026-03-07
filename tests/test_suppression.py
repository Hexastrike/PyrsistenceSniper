from __future__ import annotations

from pyrsistencesniper.models.finding import AllowRule, Finding

# The old _is_auto_suppressed function has been replaced by plugin-level
# AllowRule entries with signer= and not_lolbin= fields.  These tests verify
# that the same filtering behaviour is achieved through AllowRule.matches().

_MS_RULE = AllowRule(signer="microsoft", not_lolbin=True)

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
    rule = AllowRule(value_contains="explorer.exe", signer="microsoft")
    finding = Finding(value="explorer.exe", signer="Microsoft Windows")
    assert rule.matches(finding) is True


def test_value_match_but_unsigned_no_match() -> None:
    rule = AllowRule(value_contains="explorer.exe", signer="microsoft")
    finding = Finding(value="explorer.exe", signer="")
    assert rule.matches(finding) is False


def test_value_match_but_wrong_signer_no_match() -> None:
    rule = AllowRule(value_contains="explorer.exe", signer="microsoft")
    finding = Finding(value="explorer.exe", signer="Evil Corp")
    assert rule.matches(finding) is False
