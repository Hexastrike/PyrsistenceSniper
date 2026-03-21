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
class TimeProviders(PersistencePlugin):
    definition = CheckDefinition(
        id="time_providers",
        technique="Time Providers",
        mitre_id="T1547.003",
        description=(
            "Time provider DLLs are loaded by the W32Time service at "
            "startup. Default providers are NtpClient, NtpServer, and "
            "VMICTimeProvider (Hyper-V). Any non-default time provider "
            "DLL is a strong indicator of persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1547/003/",),
        allow=(
            FilterRule(
                reason="Default Windows time provider",
                value_matches=r"w32time\.dll$",
                signer="microsoft",
            ),
            FilterRule(
                reason="Hyper-V time provider",
                value_matches=r"vmictimeprovider\.dll$",
                signer="microsoft",
            ),
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\W32Time\TimeProviders",
                values="DllName",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )
