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
    definition = CheckDefinition(
        id="snmp_extension_agent",
        technique="SNMP Extension Agent DLL",
        mitre_id="T1574",
        description=(
            "SNMP ExtensionAgents values specify registry paths to DLL "
            "specifications loaded by the SNMP service. Legitimate "
            "defaults include inetmib1.dll, snmpmib.dll, hostmib.dll. "
            "Any non-default agent DLL is suspicious."
        ),
        references=("https://attack.mitre.org/techniques/T1574/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\SNMP\Parameters\ExtensionAgents",
                scope=HiveScope.HKLM,
            ),
        ),
    )
