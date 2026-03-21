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

_CTX_MENU_PATHS: tuple[str, ...] = (
    r"SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers",
    r"SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
    r"SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers",
)


@register_plugin
class ExplorerContextMenu(PersistencePlugin):
    definition = CheckDefinition(
        id="explorer_context_menu",
        technique="Explorer Context Menu Handlers",
        mitre_id="T1547.001",
        description=(
            "Context-menu shell extensions (ContextMenuHandlers) are COM "
            "DLLs loaded by Explorer on right-click. Registering a "
            "malicious handler provides DLL-based persistence under SYSTEM "
            "or the invoking user."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        allow=(
            FilterRule(
                reason="Built-in context menu handler",
                value_matches=r"(\\system32\\|\\Windows Defender\\)",
                signer="microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Built-in shell extension DLL",
                value_matches=r"(shell32|ieframe)\.dll$",
                signer="microsoft",
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self.hive_ops.open_hive("SOFTWARE")
        if hive is None:
            return findings

        for ctx_path in _CTX_MENU_PATHS:
            rel_path = ctx_path.split("\\", 1)[1] if "\\" in ctx_path else ctx_path
            tree = self.registry.load_subtree(hive, rel_path)
            if tree is None:
                continue

            for handler, node in tree.children():
                value_str = registry_value_to_str(node.get("(Default)"))
                if value_str is None:
                    continue

                dll_path = self.hive_ops.resolve_clsid_inproc(hive, value_str)
                if dll_path:
                    value_str = dll_path
                elif "\\" not in value_str and not value_str.startswith("{"):
                    continue  # Skip non-path, non-CLSID handler names

                findings.append(
                    self._make_finding(
                        path=f"HKLM\\{ctx_path}\\{handler}",
                        value=value_str,
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
