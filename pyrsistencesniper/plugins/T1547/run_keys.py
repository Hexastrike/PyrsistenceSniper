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
class RunKeys(PersistencePlugin):
    definition = CheckDefinition(
        id="run_keys",
        technique="Registry Run Keys",
        mitre_id="T1547.001",
        description=(
            "Run, RunOnce, RunEx, and RunOnceEx registry keys execute "
            "listed programs at user logon. Both native and WoW64 paths "
            "are checked, including the Policies\\Explorer\\Run override."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx",
                scope=HiveScope.HKLM,
            ),
        ),
        allow=(
            FilterRule(
                reason="Windows Security Health tray is a built-in autorun",
                value_contains="SecurityHealthSystray",
            ),
            FilterRule(
                reason="Microsoft-signed autorun", signer="microsoft", not_lolbin=True
            ),
        ),
    )
