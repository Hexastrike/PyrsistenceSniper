from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, FilterRule, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

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
        allow=(
            FilterRule(
                reason="Built-in disk cleanup handler",
                value_matches=r"\\system32\\",
                signer="microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Built-in disk cleanup DLL",
                value_matches=r"(ieframe|shell32|dataclen|setupcln)\.dll$",
            ),
        ),
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
