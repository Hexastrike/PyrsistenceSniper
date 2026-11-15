"""Detection for Explorer Context Menu Handlers."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
)
from pyrsistencesniper.core.registry import registry_key_join, registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_CTX_MENU_SUBJECTS: tuple[str, ...] = (
    "Directory",
    r"Directory\Background",
    "Folder",
    "Drive",
    "AllFilesystemObjects",
    "*",
)
_SHELLEX_SUFFIX = r"shellex\ContextMenuHandlers"
_MACHINE_CLASSES_ROOT = "Classes"
_CLSID_ROOTS: tuple[str, ...] = ("CLSID", r"Wow6432Node\CLSID")

_ClsidLookup = tuple[HiveProtocol, str]


@register_plugin
class ExplorerContextMenu(PersistencePlugin):
    """Detects Explorer Context Menu Handlers persistence entries."""

    definition = CheckDefinition(
        id="explorer_context_menu",
        technique="Explorer Context Menu Handlers",
        mitre_id="T1547.001",
        description=(
            "ContextMenuHandlers are COM DLLs Explorer loads on right-click. A handler "
            "registered in a user's UsrClass.dat wins over the machine-wide "
            "SOFTWARE\\Classes entry and needs no administrator rights."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
    )

    def run(self) -> list[Finding]:
        """Report context menu handlers from both halves of the merged HKCR."""
        findings: list[Finding] = []

        machine_lookups: tuple[_ClsidLookup, ...] = ()
        machine_hive = self.context.open_hive_by_name("SOFTWARE")
        if machine_hive is not None:
            machine_lookups = ((machine_hive, _MACHINE_CLASSES_ROOT),)
            self._scan_hive(
                machine_hive,
                _MACHINE_CLASSES_ROOT,
                "HKLM\\SOFTWARE\\Classes",
                AccessLevel.SYSTEM,
                machine_lookups,
                findings,
            )

        for profile, user_hive in self.context.iter_usrclass_hives():
            self._scan_hive(
                user_hive,
                "",
                f"HKU\\{profile.username}\\Software\\Classes",
                AccessLevel.USER,
                ((user_hive, ""), *machine_lookups),
                findings,
            )

        return findings

    def _scan_hive(
        self,
        hive: HiveProtocol,
        lookup_root: str,
        display_root: str,
        access: AccessLevel,
        clsid_lookups: tuple[_ClsidLookup, ...],
        findings: list[Finding],
    ) -> None:
        """Scan one hive's class registrations for context menu handlers."""
        for subject in _CTX_MENU_SUBJECTS:
            tree = self.registry.load_subtree(
                hive, registry_key_join(lookup_root, subject, _SHELLEX_SUFFIX)
            )
            if tree is None:
                continue

            for handler, node in tree.children():
                value_str = registry_value_to_str(node.get("(Default)"))
                if value_str is None:
                    continue

                dll_path = self._resolve_handler_dll(clsid_lookups, value_str)
                if dll_path:
                    value_str = dll_path
                elif "\\" not in value_str and not value_str.startswith("{"):
                    continue

                findings.append(
                    self._make_finding(
                        path=registry_key_join(
                            display_root, subject, _SHELLEX_SUFFIX, handler
                        ),
                        value=value_str,
                        access=access,
                    )
                )

    def _resolve_handler_dll(
        self, clsid_lookups: tuple[_ClsidLookup, ...], clsid: str
    ) -> str:
        """Look a handler CLSID up in every class store and registry view offered."""
        if not clsid.startswith("{"):
            return ""
        for lookup_hive, lookup_root in clsid_lookups:
            for clsid_root in _CLSID_ROOTS:
                dll_path = self.context.resolve_clsid_default(
                    lookup_hive,
                    registry_key_join(lookup_root, clsid_root, clsid, "InprocServer32"),
                )
                if dll_path:
                    return dll_path
        return ""
