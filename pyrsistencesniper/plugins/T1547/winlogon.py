"""Detection for the Winlogon logon-helper registry surface (T1547.004)."""

from __future__ import annotations

from dataclasses import replace

from pyrsistencesniper.core.models import (
    CheckDefinition,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


def _split_command_list(value: str) -> list[str]:
    """Split a comma-delimited Winlogon command list into its components."""
    return [component.strip() for component in value.split(",") if component.strip()]


# Splitting is not cosmetic: the shipped Userinit is written "userinit.exe," and
# the trailing comma stops the whole value from resolving, so the legitimate
# default would be reported unsigned on every host.
class _CommaSeparatedWinlogonValue(PersistencePlugin):
    """Base for Winlogon values Windows itself parses as a comma-delimited list."""

    def run(self) -> list[Finding]:
        """Emit one finding per component so each resolves on its own merits."""
        return [
            replace(finding, value=component)
            for finding in super().run()
            for component in _split_command_list(finding.value)
        ]


@register_plugin
class WinlogonShell(PersistencePlugin):
    """Detects Winlogon Shell persistence entries."""

    definition = CheckDefinition(
        id="winlogon_shell",
        technique="Winlogon Shell",
        mitre_id="T1547.004",
        description=(
            "The Winlogon Shell value names the shell started after authentication. "
            "The default is 'explorer.exe'."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                values="Shell",
                scope=HiveScope.BOTH,
            ),
        ),
    )


@register_plugin
class WinlogonUserinit(_CommaSeparatedWinlogonValue):
    """Detects Winlogon Userinit persistence entries."""

    definition = CheckDefinition(
        id="winlogon_userinit",
        technique="Winlogon Userinit",
        mitre_id="T1547.004",
        description=(
            "The Userinit value is a comma-delimited list of programs run immediately "
            "after user authentication. The default is userinit.exe alone."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
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
    """Detects Winlogon MPNotify persistence entries."""

    definition = CheckDefinition(
        id="winlogon_mpnotify",
        technique="Winlogon MPNotify",
        mitre_id="T1547.004",
        description=(
            "The mpnotify value names the notification program Winlogon starts after "
            "authentication. The value is rarely set."
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
    """Detects Winlogon Notify notification-package DLL registrations."""

    definition = CheckDefinition(
        id="winlogon_notify_packages",
        technique="Winlogon Notify Packages",
        mitre_id="T1547.004",
        description=(
            "Each subkey of Winlogon\\Notify registers a DllName that "
            "Winlogon loads into its own process and calls on logon, "
            "logoff, lock and unlock events, running as SYSTEM."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
                values="DllName",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )


@register_plugin
class WinlogonAppSetup(_CommaSeparatedWinlogonValue):
    """Detects Winlogon AppSetup persistence entries."""

    definition = CheckDefinition(
        id="winlogon_appsetup",
        technique="Winlogon AppSetup",
        mitre_id="T1547.004",
        description=(
            "AppSetup holds a comma-delimited list of programs Winlogon "
            "runs in the SYSTEM context at every interactive logon, "
            "before the shell starts."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                values="AppSetup",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WinlogonSystem(_CommaSeparatedWinlogonValue):
    """Detects Winlogon System persistence entries."""

    definition = CheckDefinition(
        id="winlogon_system",
        technique="Winlogon System",
        mitre_id="T1547.004",
        description=(
            "The System value holds a comma-delimited list of programs Winlogon starts "
            "in the system context during initialization, and is empty on a default "
            "installation."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                values="System",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WinlogonTaskman(PersistencePlugin):
    """Detects Winlogon Taskman persistence entries."""

    definition = CheckDefinition(
        id="winlogon_taskman",
        technique="Winlogon Taskman",
        mitre_id="T1547.004",
        description=(
            "Taskman names the executable launched in place of Task Manager. It is "
            "unset by default."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                values="Taskman",
                scope=HiveScope.BOTH,
            ),
        ),
    )


@register_plugin
class WinlogonVMApplet(PersistencePlugin):
    """Detects Winlogon VMApplet persistence entries."""

    definition = CheckDefinition(
        id="winlogon_vmapplet",
        technique="Winlogon VMApplet",
        mitre_id="T1547.004",
        description=(
            "VMApplet names the program Winlogon runs, as SYSTEM, when the system runs "
            "out of virtual memory."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                values="VMApplet",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WinlogonGinaDll(PersistencePlugin):
    """Detects Winlogon GinaDLL persistence entries."""

    definition = CheckDefinition(
        id="winlogon_gina_dll",
        technique="Winlogon GinaDLL",
        mitre_id="T1547.004",
        description=(
            "GinaDLL replaces the Graphical Identification and "
            "Authentication library Winlogon loads. Windows Vista and "
            "later ignore it, so any value on a modern image is a "
            "leftover or a credential-capture attempt."
        ),
        references=("https://attack.mitre.org/techniques/T1547/004/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                values="GinaDLL",
                scope=HiveScope.HKLM,
            ),
        ),
    )
