"""Detection for Network Provider DLL."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SERVICES_PATH_TEMPLATE = r"{controlset}\Services"


@register_plugin
class NetworkProviderDll(PersistencePlugin):
    """Detects Network Provider DLL persistence entries."""

    definition = CheckDefinition(
        id="network_provider_dll",
        technique="Network Provider DLL",
        mitre_id="T1556.008",
        description=(
            "Network provider DLLs are loaded during logon to handle network "
            "authentication, and receive the user's plaintext credentials. The default "
            "providers include LanmanWorkstation (ntlanman.dll) and webclient "
            "(davclnt.dll)."
        ),
    )

    def run(self) -> list[Finding]:
        """Report the ProviderPath DLL every network provider service registers."""
        findings: list[Finding] = []

        services_path = _SERVICES_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.context.load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for service_name, node in tree.children():
            provider_node = node.child("NetworkProvider")
            if provider_node is None:
                continue
            value_str = registry_value_to_str(provider_node.get("ProviderPath"))
            if value_str is None:
                continue
            findings.append(
                self._make_finding(
                    path=(
                        f"HKLM\\SYSTEM\\{services_path}"
                        f"\\{service_name}\\NetworkProvider\\ProviderPath"
                    ),
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
