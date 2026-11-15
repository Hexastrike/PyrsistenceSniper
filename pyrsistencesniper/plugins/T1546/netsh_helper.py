"""Detection for Netsh Helper DLL."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class NetshHelper(PersistencePlugin):
    """Detects Netsh Helper DLL persistence entries."""

    definition = CheckDefinition(
        id="netsh_helper",
        technique="Netsh Helper DLL",
        mitre_id="T1546.007",
        description=(
            "Netsh helper DLLs registered under HKLM\\SOFTWARE\\Microsoft\\NetSh are "
            "loaded every time netsh.exe runs."
        ),
        references=("https://attack.mitre.org/techniques/T1546/007/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\NetSh",
                scope=HiveScope.HKLM,
            ),
        ),
    )
