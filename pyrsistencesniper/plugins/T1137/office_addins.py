"""Detect Office add-in persistence via HKLM and per-user NTUSER hives.

Checks Manifest, FileName, and Path values under per-application Addins
keys across all Office applications.  Also detects AI add-in hijacking
through ClickToRun registry paths.
"""

from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

_OFFICE_APPS: tuple[str, ...] = (
    "Word",
    "Excel",
    "PowerPoint",
    "Outlook",
    "Access",
)


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

        hive = self._open_hive("SOFTWARE")
        if hive is not None:
            for app in _OFFICE_APPS:
                addins_path = f"Microsoft\\Office\\{app}\\Addins"
                tree = self.registry.load_subtree(hive, addins_path)
                if tree is None:
                    continue
                for addin, node in tree.children():
                    for val_name in ("Manifest", "FileName", "Path"):
                        val = node.get(val_name)
                        if val is not None:
                            findings.append(
                                self._make_finding(
                                    path=f"HKLM\\SOFTWARE\\{addins_path}\\{addin}\\{val_name}",
                                    value=str(val),
                                    access=AccessLevel.SYSTEM,
                                )
                            )

        for profile, uhive in self._iter_user_hives():
            for app in _OFFICE_APPS:
                addins_path = f"Software\\Microsoft\\Office\\{app}\\Addins"
                tree = self.registry.load_subtree(uhive, addins_path)
                if tree is None:
                    continue
                for addin, node in tree.children():
                    for val_name in ("Manifest", "FileName", "Path"):
                        val = node.get(val_name)
                        if val is not None:
                            findings.append(
                                self._make_finding(
                                    path=f"HKU\\{profile.username}\\{addins_path}\\{addin}\\{val_name}",
                                    value=str(val),
                                    access=AccessLevel.USER,
                                )
                            )

        return findings


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
        tree = self._load_subtree("SOFTWARE", ai_path)
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
