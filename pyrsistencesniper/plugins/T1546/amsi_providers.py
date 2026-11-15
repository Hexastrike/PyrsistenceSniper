"""Detection for AMSI Provider DLL."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_AMSI_PATH = r"Microsoft\AMSI\Providers"

_UNRESOLVED_DESCRIPTION = (
    "An AMSI provider is registered whose CLSID has no InprocServer32 COM "
    "server in either registry view of the SOFTWARE hive. The provider is "
    "loaded into every process that invokes AMSI, but the DLL it loads is "
    "registered somewhere this image does not cover - a per-user class "
    "registration, or a CLSID key removed after the provider was written."
)


@register_plugin
class AmsiProviders(PersistencePlugin):
    """Detects AMSI Provider DLL persistence entries."""

    definition = CheckDefinition(
        id="amsi_providers",
        technique="AMSI Provider DLL",
        mitre_id="T1546.015",
        description=(
            "AMSI providers are COM DLLs the Antimalware Scan Interface loads into "
            "every process that invokes AMSI, where a provider sees every scan "
            "request."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every registered AMSI provider with the COM server it loads."""
        findings: list[Finding] = []

        hive = self.context.open_hive_by_name("SOFTWARE")
        if hive is None:
            return findings

        tree = self.context.load_subtree("SOFTWARE", _AMSI_PATH)
        if tree is None:
            return findings

        for clsid, _node in tree.children():
            dll_path = self._provider_dll(hive, clsid)
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_AMSI_PATH}\\{clsid}",
                    value=dll_path or clsid,
                    access=AccessLevel.SYSTEM,
                    description="" if dll_path else _UNRESOLVED_DESCRIPTION,
                )
            )

        return findings

    def _provider_dll(self, hive: HiveProtocol, clsid: str) -> str:
        """Return a provider's COM server path from either registry view."""
        native_path = self.context.resolve_clsid_inproc(hive, clsid)
        if native_path or not clsid.startswith("{"):
            return native_path
        return self.context.resolve_clsid_default(
            hive, f"Classes\\Wow6432Node\\CLSID\\{clsid}\\InprocServer32"
        )
