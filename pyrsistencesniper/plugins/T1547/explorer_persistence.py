"""Detection for Explorer autostart, browser helper object, and app key abuse."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class ExplorerLoad(PersistencePlugin):
    """Detects Explorer Load Value persistence entries."""

    definition = CheckDefinition(
        id="explorer_load",
        technique="Explorer Load Value",
        mitre_id="T1547.001",
        description=(
            "The Load value under Windows NT\\CurrentVersion\\Windows names a program "
            "started at user logon, in that user's context."
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                values="Load",
                scope=HiveScope.BOTH,
            ),
        ),
    )


_BHO_PATH = r"Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"


@register_plugin
class ExplorerBrowserHelperObjects(PersistencePlugin):
    """Detects Browser Helper Objects persistence entries."""

    definition = CheckDefinition(
        id="explorer_bho",
        technique="Browser Helper Objects",
        mitre_id="T1547.001",
        description=(
            "Browser Helper Objects are COM DLLs registered under Explorer\\Browser "
            "Helper Objects and loaded into Explorer, and historically Internet "
            "Explorer."
        ),
    )

    def run(self) -> list[Finding]:
        """Report the DLL behind every registered Browser Helper Object."""
        findings: list[Finding] = []

        hive = self.context.open_hive_by_name("SOFTWARE")
        if hive is None:
            return findings

        tree = self.registry.load_subtree(hive, _BHO_PATH)
        if tree is None:
            return findings

        for clsid, _node in tree.children():
            inproc_path = f"Classes\\CLSID\\{clsid}\\InprocServer32"
            dll_path = self.context.resolve_clsid_default(hive, inproc_path)

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_BHO_PATH}\\{clsid}",
                    value=dll_path or clsid,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings


_APP_KEY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey"
_APP_KEY_VALUES: tuple[str, ...] = ("ShellExecute", "Association")


@register_plugin
class ExplorerAppKey(PersistencePlugin):
    """Detects Explorer AppKey Override persistence entries."""

    definition = CheckDefinition(
        id="explorer_app_key",
        technique="Explorer AppKey Override",
        mitre_id="T1547.001",
        description=(
            "Explorer AppKey entries bind special keyboard keys, such as the mail and "
            "browser keys, to a program through their ShellExecute or Association "
            "value, which runs when the key is pressed."
        ),
    )

    def run(self) -> list[Finding]:
        """Report the programs AppKey binds to the special keyboard keys."""
        findings: list[Finding] = []

        tree = self.context.load_subtree(
            "SOFTWARE",
            r"Microsoft\Windows\CurrentVersion\Explorer\AppKey",
        )
        if tree is None:
            return findings

        for key_id, node in tree.children():
            for value_name in _APP_KEY_VALUES:
                raw_value = node.get(value_name)
                if raw_value is None:
                    continue
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\{_APP_KEY_PATH}\\{key_id}\\{value_name}",
                        value=str(raw_value),
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
