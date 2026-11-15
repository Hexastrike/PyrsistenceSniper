"""Detection for NL6 ContentIndex DLL Override."""

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
    """Detects NL6 ContentIndex DLL Override persistence entries."""

    definition = CheckDefinition(
        id="content_index_dll",
        technique="NL6 ContentIndex DLL Override",
        mitre_id="T1574",
        description=(
            "DLLOverridePath under a ContentIndex\\Language subkey names a DLL the "
            "Windows Search indexer loads in place of the default NL6 content indexing "
            "DLL. The value is normally absent."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every ContentIndex language that overrides its NL6 DLL."""
        findings: list[Finding] = []

        lang_path = _CONTENT_INDEX_LANG_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.context.load_subtree("SYSTEM", lang_path)
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
