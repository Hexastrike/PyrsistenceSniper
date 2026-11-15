"""Detection for App Paths Hijack."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_APP_PATHS = r"Microsoft\Windows\CurrentVersion\App Paths"


@register_plugin
class AppPaths(PersistencePlugin):
    """Detects App Paths Hijack persistence entries."""

    definition = CheckDefinition(
        id="app_paths",
        technique="App Paths Hijack",
        mitre_id="T1546",
        description=(
            "App Paths entries map a short executable name to a full path, so an entry "
            "decides which binary starts when that name is launched."
        ),
    )

    def run(self) -> list[Finding]:
        """Report the executable each App Paths entry maps a program name onto."""
        findings: list[Finding] = []

        tree = self.context.load_subtree("SOFTWARE", _APP_PATHS)
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
