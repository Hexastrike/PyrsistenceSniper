from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel, AllowRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_APP_PATHS = r"Microsoft\Windows\CurrentVersion\App Paths"


@register_plugin
class AppPaths(PersistencePlugin):
    definition = CheckDefinition(
        id="app_paths",
        technique="App Paths Hijack",
        mitre_id="T1546",
        description=(
            "App Paths entries map short executable names to full "
            "filesystem paths. Registering or hijacking an entry redirects "
            "legitimate program launches to a malicious binary."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
        allow=(
            AllowRule(
                reason="Microsoft-signed application",
                signer="microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree("SOFTWARE", _APP_PATHS)
        if tree is None:
            return findings

        for app_name, node in tree.children():
            value_str = self._to_str(node.get("(Default)"))
            if value_str is None:
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_APP_PATHS}\\{app_name}",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
