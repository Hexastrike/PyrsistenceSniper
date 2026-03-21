"""Detect Office add-in persistence via HKLM and per-user NTUSER hives.

Checks Manifest, FileName, and Path values under per-application Addins
keys across all Office applications.  Also detects AI add-in hijacking
through ClickToRun registry paths.
"""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_OFFICE_APPS: tuple[str, ...] = (
    "Word",
    "Excel",
    "PowerPoint",
    "Outlook",
    "Access",
)

_OFFICE_VERSIONS: tuple[str, ...] = ("", "14.0", "15.0", "16.0")


@register_plugin
class OfficeAddins(PersistencePlugin):
    definition = CheckDefinition(
        id="office_addins",
        technique="Office Add-in Registration",
        mitre_id="T1137.006",
        description=(
            "Office add-in registrations (Manifest, FileName, Path values) "
            "under per-application Addins keys specify DLLs and manifests "
            "loaded at application startup. Both HKLM and per-user NTUSER "
            "hives are checked across all Office applications."
        ),
        references=("https://attack.mitre.org/techniques/T1137/006/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self.hive_ops.open_hive("SOFTWARE")
        if hive is not None:
            self._scan_addins_hive(
                hive,
                "Microsoft\\Office",
                "HKLM\\SOFTWARE",
                AccessLevel.SYSTEM,
                findings,
            )

        for profile, uhive in self.hive_ops.iter_user_hives():
            self._scan_addins_hive(
                uhive,
                "Software\\Microsoft\\Office",
                f"HKU\\{profile.username}",
                AccessLevel.USER,
                findings,
            )

        return findings

    def _scan_addins_hive(
        self,
        hive: HiveProtocol,
        base_path: str,
        path_prefix: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        for app in _OFFICE_APPS:
            for version in _OFFICE_VERSIONS:
                ver_seg = f"{version}\\" if version else ""
                addins_path = f"{base_path}\\{ver_seg}{app}\\Addins"
                tree = self.registry.load_subtree(hive, addins_path)
                if tree is None:
                    continue
                for addin, node in tree.children():
                    for val_name in ("Manifest", "FileName", "Path"):
                        val = node.get(val_name)
                        if val is not None:
                            findings.append(
                                self._make_finding(
                                    path=f"{path_prefix}\\{addins_path}\\{addin}\\{val_name}",
                                    value=str(val),
                                    access=access,
                                )
                            )


@register_plugin
class OfficeAiHijack(PersistencePlugin):
    definition = CheckDefinition(
        id="office_ai_hijack",
        technique="Office AI Add-in Hijack",
        mitre_id="T1137.006",
        description=(
            "Office AI add-in registrations under ClickToRun\\REGISTRY "
            "paths can be hijacked to redirect COM loading to malicious "
            "DLLs when AI features are invoked."
        ),
        references=("https://attack.mitre.org/techniques/T1137/006/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        ai_path = (
            r"Microsoft\Office\ClickToRun\REGISTRY\MACHINE"
            r"\Software\Microsoft\Office\16.0\Common\AI"
        )
        tree = self.hive_ops.load_subtree("SOFTWARE", ai_path)
        if tree is None:
            return findings

        for name, val in tree.values():
            if val is not None:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\SOFTWARE\\{ai_path}\\{name}",
                        value=str(val),
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
