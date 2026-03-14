from __future__ import annotations

from pyrsistencesniper.models.finding import FilterRule, Finding
from pyrsistencesniper.plugins import _PLUGIN_REGISTRY, _discover_plugins

# -- FilterRule.not_lolbin field -----------------------------------------------


def test_not_lolbin_blocks_lolbin() -> None:
    rule = FilterRule(signer="microsoft", not_lolbin=True)
    finding = Finding(
        value="powershell.exe", signer="Microsoft Windows", is_lolbin=True
    )
    assert rule.matches(finding) is False


def test_not_lolbin_blocks_unresolved() -> None:
    rule = FilterRule(signer="microsoft", not_lolbin=True)
    finding = Finding(value="unknown.exe", signer="Microsoft Windows", is_lolbin=None)
    assert rule.matches(finding) is False


def test_not_lolbin_allows_non_lolbin() -> None:
    rule = FilterRule(signer="microsoft", not_lolbin=True)
    finding = Finding(value="svchost.exe", signer="Microsoft Windows", is_lolbin=False)
    assert rule.matches(finding) is True


# -- signer substring matching -----------------------------------------------


def test_signer_substring_match() -> None:
    rule = FilterRule(signer="microsoft")
    finding = Finding(value="test.exe", signer="Microsoft Corporation")
    assert rule.matches(finding) is True


def test_signer_substring_no_match() -> None:
    rule = FilterRule(signer="microsoft")
    finding = Finding(value="test.exe", signer="Evil Corp")
    assert rule.matches(finding) is False


def test_signer_empty_no_match() -> None:
    rule = FilterRule(signer="microsoft")
    finding = Finding(value="test.exe", signer="")
    assert rule.matches(finding) is False


# -- plugin allow rules cover old known defaults ------------------------------


def test_winlogon_shell_allows_explorer() -> None:
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["winlogon_shell"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(
        value="explorer.exe",
        check_id="winlogon_shell",
        signer="Microsoft Windows",
    )
    assert any(r.matches(finding) for r in allow_rules)


def test_winlogon_shell_blocks_unsigned_explorer() -> None:
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["winlogon_shell"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(
        value="explorer.exe",
        check_id="winlogon_shell",
        signer="",
    )
    assert not any(r.matches(finding) for r in allow_rules)


def test_winlogon_userinit_allows_signed() -> None:
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["winlogon_userinit"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(
        value=r"C:\Windows\system32\userinit.exe,",
        check_id="winlogon_userinit",
        signer="Microsoft Windows",
    )
    assert any(r.matches(finding) for r in allow_rules)


def test_winlogon_userinit_blocks_unsigned() -> None:
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["winlogon_userinit"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(
        value=r"C:\Windows\system32\userinit.exe,",
        check_id="winlogon_userinit",
        signer="",
    )
    assert not any(r.matches(finding) for r in allow_rules)


def test_rdp_wds_allows_rdpclip() -> None:
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["rdp_wds_startup"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(value="rdpclip", check_id="rdp_wds_startup")
    assert any(r.matches(finding) for r in allow_rules)


def test_lsa_extensions_allows_lsasrv() -> None:
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["lsa_extensions"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(value="lsasrv.dll", check_id="lsa_extensions")
    assert any(r.matches(finding) for r in allow_rules)


def test_msdtc_allows_xa80() -> None:
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["msdtc_xa_dll"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(value="xa80.dll", check_id="msdtc_xa_dll")
    assert any(r.matches(finding) for r in allow_rules)


def test_service_failure_allows_not_used() -> None:
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["service_failure_command"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(value="not used", check_id="service_failure_command")
    assert any(r.matches(finding) for r in allow_rules)


def test_services_allow_svchost_hosted() -> None:
    """svchost -k pattern should match the svchost rule."""
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["windows_service_image_path"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(
        value=r"%SystemRoot%\system32\svchost.exe -k netsvcs -p",
        signer="Microsoft Windows",
        is_lolbin=False,
    )
    assert any(r.matches(finding) for r in allow_rules)


def test_services_keep_non_system32() -> None:
    """Non-system32 binaries should not match any rule."""
    _discover_plugins()
    plugin_cls = _PLUGIN_REGISTRY["windows_service_image_path"]
    allow_rules = plugin_cls.definition.allow
    finding = Finding(
        value="malware.exe",
        signer="",
        is_lolbin=False,
    )
    assert not any(r.matches(finding) for r in allow_rules)
