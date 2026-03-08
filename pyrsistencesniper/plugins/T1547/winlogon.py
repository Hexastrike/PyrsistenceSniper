from __future__ import annotations

from pyrsistencesniper.models.finding import FilterRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class WinlogonShell(PersistencePlugin):
    definition = CheckDefinition(
        id="winlogon_shell",
        technique="Winlogon Shell",
        mitre_id="T1547.004",
        description=(
            "The Winlogon Shell value defines the user-mode shell launched "
            "after authentication. Replacing the default 'explorer.exe' "
            "executes an attacker binary at every logon."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        allow=(
            FilterRule(
                reason="Default Windows shell",
                value_contains="explorer.exe",
                signer="microsoft",
            ),
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                values="Shell",
                scope=HiveScope.BOTH,
            ),
        ),
    )


@register_plugin
class WinlogonUserinit(PersistencePlugin):
    definition = CheckDefinition(
        id="winlogon_userinit",
        technique="Winlogon Userinit",
        mitre_id="T1547.004",
        description=(
            "The Userinit value runs programs immediately after user "
            "authentication. Appending entries beyond the default "
            "userinit.exe provides stealthy logon persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        allow=(
            FilterRule(
                reason="Default Windows userinit",
                value_contains="userinit.exe",
                signer="microsoft",
            ),
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                values="Userinit",
                scope=HiveScope.BOTH,
            ),
        ),
    )


@register_plugin
class WinlogonMPNotify(PersistencePlugin):
    definition = CheckDefinition(
        id="winlogon_mpnotify",
        technique="Winlogon MPNotify",
        mitre_id="T1547.004",
        description=(
            "The mpnotify value specifies a notification DLL loaded by "
            "Winlogon after authentication. Any value present is "
            "suspicious as this mechanism is rarely used legitimately."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                values="mpnotify",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WinlogonNotifyPackages(PersistencePlugin):
    definition = CheckDefinition(
        id="winlogon_notify_packages",
        technique="Winlogon Notify Packages",
        mitre_id="T1547.004",
        description=(
            "LSA Notification Packages are DLLs loaded during "
            "authentication events. A non-default package may capture "
            "credentials or provide persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        allow=(
            FilterRule(reason="Default notification package", value_contains="scecli"),
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Lsa",
                values="Notification Packages",
                scope=HiveScope.HKLM,
            ),
        ),
    )
