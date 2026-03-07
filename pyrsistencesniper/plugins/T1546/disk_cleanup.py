from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel, AllowRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_VOLUME_CACHES_PATH = r"Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"


@register_plugin
class DiskCleanupHandler(PersistencePlugin):
    definition = CheckDefinition(
        id="disk_cleanup_handler",
        technique="Disk Cleanup Handler Hijack",
        mitre_id="T1546.015",
        description=(
            "Disk Cleanup VolumeCaches handlers are COM objects loaded "
            "when cleanmgr.exe runs. Replacing the InprocServer32 DLL "
            "path for a handler CLSID provides code execution as SYSTEM "
            "during cleanup operations."
        ),
        references=("https://attack.mitre.org/techniques/T1546/015/",),
        allow=(AllowRule(signer="microsoft", not_lolbin=True),),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree("SOFTWARE", _VOLUME_CACHES_PATH)
        if tree is None:
            return findings

        hive = self._open_hive("SOFTWARE")
        if hive is None:
            return findings

        for handler, node in tree.children():
            val = node.get("(Default)")
            clsid = str(val) if val else ""

            if not clsid or not clsid.startswith("{"):
                continue

            inproc_path = f"Classes\\CLSID\\{clsid}\\InprocServer32"
            dll_path = self._resolve_clsid_default(hive, inproc_path)

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
