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
class NetshHelper(PersistencePlugin):
    definition = CheckDefinition(
        id="netsh_helper",
        technique="Netsh Helper DLL",
        mitre_id="T1546.007",
        description=(
            "Netsh helper DLLs registered under HKLM\\SOFTWARE\\Microsoft"
            "\\NetSh are loaded every time netsh.exe executes. A malicious "
            "helper provides persistent code execution in a "
            "network-administration context."
        ),
        references=("https://attack.mitre.org/techniques/T1546/007/",),
        allow=(
            AllowRule(
                reason="Microsoft-signed netsh helper",
                signer="microsoft",
                not_lolbin=True,
            ),
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\NetSh",
                scope=HiveScope.HKLM,
            ),
        ),
    )
