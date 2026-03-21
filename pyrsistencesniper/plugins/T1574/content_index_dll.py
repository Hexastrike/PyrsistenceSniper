from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_CONTENT_INDEX_LANG_PATH_TEMPLATE = r"{controlset}\Control\ContentIndex\Language"


@register_plugin
class ContentIndexDll(PersistencePlugin):
    definition = CheckDefinition(
        id="content_index_dll",
        technique="NL6 ContentIndex DLL Override",
        mitre_id="T1574",
        description=(
            "DLLOverridePath under ContentIndex\\Language subkeys "
            "overrides the default NL6 content indexing DLL. This value "
            "is normally absent. If present, the specified DLL is loaded "
            "by the Windows Search indexer when processing content."
        ),
        references=("https://attack.mitre.org/techniques/T1574/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        lang_path = _CONTENT_INDEX_LANG_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.hive_ops.load_subtree("SYSTEM", lang_path)
        if tree is None:
            return findings

        for lang_name, lang_node in tree.children():
            value_str = registry_value_to_str(lang_node.get("DLLOverridePath"))
            if value_str is None:
                continue
            findings.append(
                self._make_finding(
                    path=(f"HKLM\\SYSTEM\\{lang_path}\\{lang_name}\\DLLOverridePath"),
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
