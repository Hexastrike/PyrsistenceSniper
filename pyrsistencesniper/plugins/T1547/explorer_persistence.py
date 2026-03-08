from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel, FilterRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding


@register_plugin
class ExplorerLoad(PersistencePlugin):
    definition = CheckDefinition(
        id="explorer_load",
        technique="Explorer Load Value",
        mitre_id="T1547.001",
        description=(
            "The Load value under Windows\\CurrentVersion\\Windows "
            "specifies a program run by Explorer at user logon, providing "
            "user-context persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
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
    definition = CheckDefinition(
        id="explorer_bho",
        technique="Browser Helper Objects",
        mitre_id="T1547.001",
        description=(
            "Browser Helper Objects (BHOs) are COM DLLs registered under "
            "Explorer\\Browser Helper Objects. Each BHO is loaded into "
            "Explorer (and historically Internet Explorer), providing "
            "persistent in-process code execution."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        allow=(FilterRule(signer="microsoft", not_lolbin=True),),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self._open_hive("SOFTWARE")
        if hive is None:
            return findings

        tree = self.registry.load_subtree(hive, _BHO_PATH)
        if tree is None:
            return findings

        for clsid, _node in tree.children():
            inproc_path = f"Classes\\CLSID\\{clsid}\\InprocServer32"
            dll_path = self._resolve_clsid_default(hive, inproc_path)

            display = dll_path or clsid

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_BHO_PATH}\\{clsid}",
                    value=display,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings


_APP_KEY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey"


@register_plugin
class ExplorerAppKey(PersistencePlugin):
    definition = CheckDefinition(
        id="explorer_app_key",
        technique="Explorer AppKey Override",
        mitre_id="T1547.001",
        description=(
            "Explorer AppKey entries map special keyboard keys (mail, "
            "browser, etc.) to custom programs. Overriding the "
            "ShellExecute or Association values provides persistence "
            "triggered by physical key presses."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree(
            "SOFTWARE",
            r"Microsoft\Windows\CurrentVersion\Explorer\AppKey",
        )
        if tree is None:
            return findings

        for key_id, node in tree.children():
            val = node.get("ShellExecute")
            if val is not None:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\{_APP_KEY_PATH}\\{key_id}\\ShellExecute",
                        value=str(val),
                        access=AccessLevel.SYSTEM,
                    )
                )

            val = node.get("Association")
            if val is not None:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\{_APP_KEY_PATH}\\{key_id}\\Association",
                        value=str(val),
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
