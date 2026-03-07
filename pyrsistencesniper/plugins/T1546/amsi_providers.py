from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel, AllowRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_AMSI_PATH = r"Microsoft\AMSI\Providers"


@register_plugin
class AmsiProviders(PersistencePlugin):
    definition = CheckDefinition(
        id="amsi_providers",
        technique="AMSI Provider DLL",
        mitre_id="T1546.015",
        description=(
            "AMSI providers are COM DLLs loaded by the Antimalware Scan "
            "Interface into every process that invokes AMSI. A malicious "
            "provider intercepts all scan requests and executes attacker "
            "code in-process."
        ),
        references=("https://attack.mitre.org/techniques/T1546/015/",),
        allow=(AllowRule(signer="microsoft", not_lolbin=True),),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self._open_hive("SOFTWARE")
        if hive is None:
            return findings

        tree = self._load_subtree("SOFTWARE", _AMSI_PATH)
        if tree is None:
            return findings

        for clsid, _node in tree.children():
            dll_path = self._resolve_clsid_inproc(hive, clsid)
            if not dll_path:
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_AMSI_PATH}\\{clsid}",
                    value=dll_path,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
