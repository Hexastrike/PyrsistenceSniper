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
            FilterRule(
                reason="Built-in netsh helper",
                value_matches=(
                    r"^(ifmon|rasmontr|authfwcfg|dhcpcmonitor|nshdnsclient"
                    r"|dot3cfg|fwcfg|hnetmon|netiohlp|netprofm|nettrace"
                    r"|nshhttp|nshipsec|nshwfp|rpcnsh|WcnNetsh|whhelper"
                    r"|wlancfg|wshelper|wwancfg|peerdistsh)\.dll$"
                ),
            ),
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\NetSh",
                scope=HiveScope.HKLM,
            ),
        ),
    )
