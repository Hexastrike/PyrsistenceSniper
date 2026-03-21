"""Detect Office internal DLL override persistence.

WwlibtDll (Word) and PPCoreTDLL (PowerPoint) registry values can be
overridden to load a malicious DLL at application startup.  All installed
Office versions are enumerated.
"""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_OVERRIDE_VALUES: tuple[str, ...] = (
    "WwlibtDll",
    "PPCoreTDLL",
)


@register_plugin
class OfficeDllOverride(PersistencePlugin):
    definition = CheckDefinition(
        id="office_dll_override",
        technique="Office DLL Override",
        mitre_id="T1137",
        description=(
            "Office internal DLL values (WwlibtDll for Word, PPCoreTDLL "
            "for PowerPoint) can be overridden in the registry to load a "
            "malicious DLL when the respective application starts. All "
            "installed Office versions are checked."
        ),
        references=("https://attack.mitre.org/techniques/T1137/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        office_tree = self.hive_ops.load_subtree("SOFTWARE", r"Microsoft\Office")
        if office_tree is None:
            return findings

        for version, version_node in office_tree.children():
            for val_name in _OVERRIDE_VALUES:
                word_node = version_node.child("Word")
                if word_node is not None:
                    val = word_node.get(val_name)
                    if val is not None:
                        findings.append(
                            self._make_finding(
                                path=f"HKLM\\SOFTWARE\\Microsoft\\Office\\{version}\\Word\\{val_name}",
                                value=str(val),
                                access=AccessLevel.SYSTEM,
                            )
                        )

                ppt_node = version_node.child("PowerPoint")
                if ppt_node is not None:
                    val = ppt_node.get(val_name)
                    if val is not None:
                        findings.append(
                            self._make_finding(
                                path=f"HKLM\\SOFTWARE\\Microsoft\\Office\\{version}\\PowerPoint\\{val_name}",
                                value=str(val),
                                access=AccessLevel.SYSTEM,
                            )
                        )

        return findings
