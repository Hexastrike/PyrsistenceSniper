"""Detection for Disk Cleanup Handler Hijack."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_VOLUME_CACHES_PATH = r"Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"


@register_plugin
class DiskCleanupHandler(PersistencePlugin):
    """Detects Disk Cleanup Handler Hijack persistence entries."""

    definition = CheckDefinition(
        id="disk_cleanup_handler",
        technique="Disk Cleanup Handler Hijack",
        mitre_id="T1546.015",
        description=(
            "Disk Cleanup VolumeCaches handlers are COM objects cleanmgr.exe loads "
            "when it runs, each through the InprocServer32 DLL its CLSID registers."
        ),
        references=("https://attack.mitre.org/techniques/T1546/015/",),
    )

    def run(self) -> list[Finding]:
        """Report the DLL behind every registered VolumeCaches cleanup handler."""
        findings: list[Finding] = []

        tree = self.context.load_subtree("SOFTWARE", _VOLUME_CACHES_PATH)
        if tree is None:
            return findings

        hive = self.context.open_hive_by_name("SOFTWARE")
        if hive is None:
            return findings

        for handler, node in tree.children():
            default_value = node.get("(Default)")
            clsid = str(default_value) if default_value else ""

            if not clsid or not clsid.startswith("{"):
                continue

            inproc_path = f"Classes\\CLSID\\{clsid}\\InprocServer32"
            dll_path = self.context.resolve_clsid_default(hive, inproc_path)

            if not dll_path:
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_VOLUME_CACHES_PATH}\\{handler}",
                    value=dll_path,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
