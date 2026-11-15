"""Detection for SNMP Extension Agent DLL."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class SnmpExtensionAgent(PersistencePlugin):
    """Detects SNMP Extension Agent DLL persistence entries."""

    definition = CheckDefinition(
        id="snmp_extension_agent",
        technique="SNMP Extension Agent DLL",
        mitre_id="T1574",
        description=(
            "SNMP ExtensionAgents values point to registry keys that name the "
            "extension agent DLLs the SNMP service loads. The defaults include "
            "inetmib1.dll, snmpmib.dll and hostmib.dll."
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\SNMP\Parameters\ExtensionAgents",
                scope=HiveScope.HKLM,
            ),
        ),
    )
