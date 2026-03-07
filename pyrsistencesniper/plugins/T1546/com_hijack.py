from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

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
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree("SOFTWARE", _CLSID_PATH)
        if tree is None:
            return findings

        for clsid, clsid_node in tree.children():
            treat_as = clsid_node.child("TreatAs")
            if treat_as is None:
                continue
            value_str = self._to_str(treat_as.get("(Default)"))
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
