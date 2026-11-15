"""Cross-cutting plugin registry and metadata tests."""

from __future__ import annotations

import re

from pyrsistencesniper.core.models import Finding, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins import _PLUGIN_REGISTRY, _discover_plugins

_MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


# Discovery records an unimportable module instead of raising, so a plugin lost to a
# broken import would leave the scan silently smaller. The exact count is the guard.
def test_exactly_130_plugins_registered() -> None:
    """Every one of the 130 plugins registers."""
    _discover_plugins()
    assert len(_PLUGIN_REGISTRY) == 130, (
        f"Expected 130 registered plugins, got {len(_PLUGIN_REGISTRY)}. "
        "Update this count when adding or removing a check; otherwise a "
        "registration was lost or duplicated."
    )


def test_all_plugins_have_complete_definitions() -> None:
    """Every registered plugin has complete CheckDefinition metadata."""
    _discover_plugins()
    for check_id, plugin_cls in _PLUGIN_REGISTRY.items():
        definition = plugin_cls.definition
        assert definition.id, f"{check_id}: missing id"
        assert definition.technique, f"{check_id}: missing technique"
        assert _MITRE_ID_RE.match(definition.mitre_id), (
            f"{check_id}: mitre_id '{definition.mitre_id}' must match "
            "T\\d{4}(\\.\\d{3})?"
        )
        description = definition.description
        assert description, f"{check_id}: missing description"
        assert len(description) > 10, (
            f"{check_id}: description must be >10 chars, got: {description!r}"
        )
        assert definition.reference_links, f"{check_id}: missing references"


_DEFAULT_PROFILE = DetectionProfile.load(None)


def test_winlogon_shell_allows_explorer() -> None:
    """The default shell would otherwise be a finding on every host scanned."""
    allow_rules = _DEFAULT_PROFILE.policy_for("winlogon_shell").allow
    finding = Finding(
        value="explorer.exe",
        check_id="winlogon_shell",
        signer="Microsoft Windows",
    )
    assert any(rule.matches(finding) for rule in allow_rules)


def test_winlogon_shell_blocks_unsigned_explorer() -> None:
    """A planted explorer.exe carries no signature, so the allowance must not apply."""
    allow_rules = _DEFAULT_PROFILE.policy_for("winlogon_shell").allow
    finding = Finding(
        value="explorer.exe",
        check_id="winlogon_shell",
        signer="",
    )
    assert not any(rule.matches(finding) for rule in allow_rules)


def test_winlogon_userinit_allows_signed() -> None:
    """The default userinit is allowed once the plugin has split off the comma."""
    allow_rules = _DEFAULT_PROFILE.policy_for("winlogon_userinit").allow
    finding = Finding(
        value=r"C:\Windows\system32\userinit.exe",
        check_id="winlogon_userinit",
        signer="Microsoft Windows",
    )
    assert any(rule.matches(finding) for rule in allow_rules)


def test_winlogon_userinit_blocks_unsigned() -> None:
    """An unsigned userinit.exe is the classic Winlogon hijack, not the default."""
    allow_rules = _DEFAULT_PROFILE.policy_for("winlogon_userinit").allow
    finding = Finding(
        value=r"C:\Windows\system32\userinit.exe",
        check_id="winlogon_userinit",
        signer="",
    )
    assert not any(rule.matches(finding) for rule in allow_rules)


def test_winlogon_userinit_rule_is_anchored() -> None:
    """A userinit.exe outside System32 is a hijack the allow rule must not cover."""
    allow_rules = _DEFAULT_PROFILE.policy_for("winlogon_userinit").allow
    for value in (
        r"C:\ProgramData\userinit.exe",
        r"C:\Windows\system32\userinit.exe.evil.exe",
        r"C:\Windows\system32\userinit.exe,C:\ProgramData\evil.exe",
    ):
        finding = Finding(
            value=value,
            check_id="winlogon_userinit",
            signer="Microsoft Windows",
        )
        assert not any(rule.matches(finding) for rule in allow_rules), value


def test_rdp_wds_allows_rdpclip() -> None:
    """rdpclip is the clipboard helper every RDP session starts, not evidence."""
    allow_rules = _DEFAULT_PROFILE.policy_for("rdp_wds_startup").allow
    finding = Finding(value="rdpclip", check_id="rdp_wds_startup")
    assert any(rule.matches(finding) for rule in allow_rules)


def test_lsa_extensions_allows_lsasrv() -> None:
    """lsasrv.dll is LSA's own module, so its presence in the list is expected."""
    allow_rules = _DEFAULT_PROFILE.policy_for("lsa_extensions").allow
    finding = Finding(
        value="lsasrv.dll", check_id="lsa_extensions", signer="Microsoft Windows"
    )
    assert any(rule.matches(finding) for rule in allow_rules)


def test_msdtc_allows_xa80() -> None:
    """xa80.dll ships with MSDTC, so only a different DLL there is worth reporting."""
    allow_rules = _DEFAULT_PROFILE.policy_for("msdtc_xa_dll").allow
    finding = Finding(value="xa80.dll", check_id="msdtc_xa_dll")
    assert any(rule.matches(finding) for rule in allow_rules)


def test_service_failure_allows_not_used() -> None:
    """The Service Control Manager writes "not used" itself when no command is set."""
    allow_rules = _DEFAULT_PROFILE.policy_for("service_failure_command").allow
    finding = Finding(value="not used", check_id="service_failure_command")
    assert any(rule.matches(finding) for rule in allow_rules)


def test_services_allow_svchost_hosted() -> None:
    """A shared-process service runs svchost -k, so the rule must cover that shape."""
    allow_rules = _DEFAULT_PROFILE.policy_for("windows_service_image_path").allow
    finding = Finding(
        value=r"%SystemRoot%\system32\svchost.exe -k netsvcs -p",
        signer="Microsoft Windows",
        is_lolbin=False,
    )
    assert any(rule.matches(finding) for rule in allow_rules)


def test_services_keep_non_system32() -> None:
    """A service image outside System32 is exactly what no allow rule may cover."""
    allow_rules = _DEFAULT_PROFILE.policy_for("windows_service_image_path").allow
    finding = Finding(
        value="malware.exe",
        signer="",
        is_lolbin=False,
    )
    assert not any(rule.matches(finding) for rule in allow_rules)


def _severity_of(check_id: str, value: str, signer: str) -> Severity:
    """Classify an unsigned-or-signed value exactly as a scan of that check would."""
    return _DEFAULT_PROFILE.policy_for(check_id).classify(
        Finding(value=value, check_id=check_id, signer=signer, is_lolbin=False)
    )


def test_explorer_context_menu_allows_real_onedrive_shell_extension() -> None:
    """Both bitnesses of the per-user OneDrive sync overlay ship on every host."""
    for value in (
        r"C:\Users\hx\AppData\Local\Microsoft\OneDrive\26.150.0804.0011"
        r"\FileSyncShell64.dll",
        r"C:\Users\hx\AppData\Local\Microsoft\OneDrive\26.150.0804.0011"
        r"\i386\FileSyncShell.dll",
    ):
        assert (
            _severity_of("explorer_context_menu", value, "Microsoft") == Severity.INFO
        ), value


def test_explorer_context_menu_onedrive_rule_is_anchored() -> None:
    """A FileSyncShell DLL outside the OneDrive install is a hijack, not the overlay."""
    for value in (
        r"C:\Users\hx\AppData\Roaming\Eviler\OneDrive\x\FileSyncShell64.dll",
        r"C:\ProgramData\OneDrive\x\FileSyncShell.dll",
        r"C:\Temp\OneDrive\a\b\c\FileSyncShell64.dll",
    ):
        assert _severity_of("explorer_context_menu", value, "") >= Severity.MEDIUM, (
            value
        )


def test_office_addins_allows_real_onedrive_integration() -> None:
    """The OneDrive Office integration add-in loads from the per-user install."""
    for value in (
        r"C:\Users\hx\AppData\Local\Microsoft\OneDrive\26.150.0804.0011"
        r"\FileCoAuthLib64.dll",
        r"C:\Users\hx\AppData\Local\Microsoft\OneDrive\26.150.0804.0011"
        r"\i386\FileCoAuthLib.dll",
    ):
        assert _severity_of("office_addins", value, "Microsoft") == Severity.INFO, value


def test_office_addins_onedrive_rule_is_anchored() -> None:
    """A Microsoft\\OneDrive directory an attacker created must not be allowed."""
    for value in (
        r"C:\Users\hx\AppData\Roaming\Microsoft\OneDrive\x\FileCoAuthLib64.dll",
        r"C:\ProgramData\Microsoft\OneDrive\x\i386\FileSyncShell.dll",
    ):
        assert _severity_of("office_addins", value, "") >= Severity.MEDIUM, value


def test_mapi32_allows_default_hotmail_provider() -> None:
    """Windows registers hmmapi.dll under Program Files on every installation."""
    for value in (
        r"%ProgramFiles%\Internet Explorer\hmmapi.dll",
        r"%ProgramFiles(x86)%\Internet Explorer\hmmapi.dll",
        r"C:\Program Files\Internet Explorer\hmmapi.dll",
        r"C:\Program Files (x86)\Internet Explorer\hmmapi.dll",
    ):
        assert _severity_of("mapi32_dll_path", value, "Microsoft") == Severity.INFO, (
            value
        )


def test_mapi32_hmmapi_rule_is_anchored() -> None:
    """An "Internet Explorer" folder anywhere else is an attacker's, not Windows'."""
    for value in (
        r"C:\Users\hx\AppData\Roaming\Internet Explorer\hmmapi.dll",
        r"C:\ProgramData\Internet Explorer\hmmapi.dll",
    ):
        assert _severity_of("mapi32_dll_path", value, "") >= Severity.MEDIUM, value


def test_typelib_allows_office_forms_cache() -> None:
    """Office regenerates MSForms.exd in the user's own temp on every form load."""
    for value in (
        r"C:\Users\hx\AppData\Local\Temp\Word8.0\MSForms.exd",
        r"C:\Users\hx\AppData\Local\Temp\Excel8.0\MSForms.exd",
    ):
        assert _severity_of("typelib_hijack", value, "") == Severity.INFO, value


def test_typelib_forms_cache_rule_is_anchored() -> None:
    """Only the real per-user temp is the cache; any other AppData tail is planted."""
    for value in (
        r"C:\ProgramData\Evil\AppData\Local\Temp\Word8.0\MSForms.exd",
        r"C:\Windows\Temp\Excel8.0\MSForms.exd",
        r"\\attacker\share\AppData\Local\Temp\Word8.0\MSForms.exd",
    ):
        assert _severity_of("typelib_hijack", value, "") >= Severity.MEDIUM, value
