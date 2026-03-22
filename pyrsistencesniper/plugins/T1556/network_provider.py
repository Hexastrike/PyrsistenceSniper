from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FilterRule,
    Finding,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SERVICES_PATH_TEMPLATE = r"{controlset}\Services"


@register_plugin
class NetworkProviderDll(PersistencePlugin):
    definition = CheckDefinition(
        id="network_provider_dll",
        technique="Network Provider DLL",
        mitre_id="T1556.008",
        description=(
            "Network provider DLLs are loaded during logon to handle "
            "network authentication. Malicious providers intercept "
            "plaintext credentials. Default providers include "
            "LanmanWorkstation (ntlanman.dll) and webclient (davclnt.dll)."
        ),
        references=("https://attack.mitre.org/techniques/T1556/008/",),
        allow=(
            FilterRule(
                reason="Default Windows network provider",
                value_matches=r"(ntlanman|davclnt|rdpnp|drprov|P9NP|vmhgfs)\.dll$",
                signer="Microsoft",
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        services_path = _SERVICES_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.hive_ops.load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for svc_name, node in tree.children():
            np_node = node.child("NetworkProvider")
            if np_node is None:
                continue
            value_str = registry_value_to_str(np_node.get("ProviderPath"))
            if value_str is None:
                continue
            findings.append(
                self._make_finding(
                    path=(
                        f"HKLM\\SYSTEM\\{services_path}"
                        f"\\{svc_name}\\NetworkProvider\\ProviderPath"
                    ),
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
