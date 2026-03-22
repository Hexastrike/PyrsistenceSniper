from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    FilterRule,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


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
                reason="Windows Security Health tray",
                value_matches=r"SecurityHealthSystray",
            ),
            FilterRule(
                reason="Realtek HD Audio service",
                value_matches=r"RtkAudUService64\.exe",
                signer="Realtek",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Waves MaxxAudio service",
                value_matches=r"WavesSvc64\.exe",
                signer="Waves",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Microsoft OneDrive auto-start",
                value_matches=r"OneDrive\\OneDrive\.exe",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Microsoft OneDrive first start",
                value_matches=r"System32\\OneDriveSetup\.exe",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Microsoft Edge WebView cleanup",
                value_matches=r"Microsoft\\EdgeWebView\\.*\\Installer\\setup\.exe",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Windows Mail address book",
                value_matches=r"Windows Mail\\wab\.exe",
                signer="Microsoft",
                not_lolbin=True,
            ),
        ),
    )
