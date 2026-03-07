from __future__ import annotations

from pyrsistencesniper.models.finding import AllowRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class ShellLauncher(PersistencePlugin):
    definition = CheckDefinition(
        id="shell_launcher",
        technique="Shell Launcher Override",
        mitre_id="T1547.001",
        description=(
            "The Shell value under Policies\\System and the IniFileMapping "
            "boot\\Shell entry override the default Windows shell "
            "(explorer.exe), executing an attacker-controlled binary at "
            "every logon."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        allow=(
            AllowRule(
                reason="Default shell launcher IniFileMapping",
                value_contains="sys:",
            ),
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Policies\Microsoft\Windows\System",
                values="Shell",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=(
                    r"SOFTWARE\Microsoft\Windows NT"
                    r"\CurrentVersion\IniFileMapping"
                    r"\system.ini\boot"
                ),
                values="Shell",
                scope=HiveScope.HKLM,
            ),
        ),
    )
