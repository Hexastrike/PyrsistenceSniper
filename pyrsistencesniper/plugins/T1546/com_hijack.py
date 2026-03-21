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

_CLSID_PATH = r"Classes\CLSID"


@register_plugin
class ComTreatAs(PersistencePlugin):
    definition = CheckDefinition(
        id="com_treat_as",
        technique="COM TreatAs Hijack",
        mitre_id="T1546.015",
        description=(
            "A TreatAs subkey under a CLSID redirects COM object "
            "instantiation to a different class. Attackers abuse this to "
            "hijack legitimate COM objects and gain code execution "
            "whenever the original CLSID is activated."
        ),
        references=("https://attack.mitre.org/techniques/T1546/015/",),
        allow=(
            FilterRule(
                reason="Standard Windows OLE TreatAs redirection",
                value_matches=r"^\{F20DA720-C02F-11CE-927B-0800095AE340\}$",
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self.hive_ops.load_subtree("SOFTWARE", _CLSID_PATH)
        if tree is None:
            return findings

        for clsid, clsid_node in tree.children():
            treat_as = clsid_node.child("TreatAs")
            if treat_as is None:
                continue
            value_str = registry_value_to_str(treat_as.get("(Default)"))
            if value_str is None:
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_CLSID_PATH}\\{clsid}\\TreatAs",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
