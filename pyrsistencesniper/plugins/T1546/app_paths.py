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
            FilterRule(
                reason="Built-in OS application",
                value_matches=r"\\system32\\",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Microsoft application in Program Files",
                value_matches=r"(?i)\\Program Files( \(x86\))?\\",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Google Chrome application path",
                value_matches=r"Google\\Chrome\\Application\\chrome\.exe",
                signer="Google",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self.hive_ops.load_subtree("SOFTWARE", _APP_PATHS)
        if tree is None:
            return findings

        for app_name, node in tree.children():
            value_str = registry_value_to_str(node.get("(Default)"))
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
