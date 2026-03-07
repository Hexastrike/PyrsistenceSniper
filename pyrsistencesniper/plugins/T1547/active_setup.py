from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel, AllowRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_ACTIVE_SETUP_PATH = r"Microsoft\Active Setup\Installed Components"


@register_plugin
class ActiveSetup(PersistencePlugin):
    definition = CheckDefinition(
        id="active_setup",
        technique="Active Setup",
        mitre_id="T1547.014",
        description=(
            "Active Setup StubPath commands run once per user at first "
            "logon. Adversaries register components under Installed "
            "Components to achieve per-user persistence with SYSTEM-level "
            "registry access."
        ),
        references=("https://attack.mitre.org/techniques/T1547/014/",),
        allow=(
            AllowRule(
                reason="Microsoft-signed active setup",
                signer="microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree("SOFTWARE", _ACTIVE_SETUP_PATH)
        if tree is None:
            return findings

        for component, node in tree.children():
            value_str = self._to_str(node.get("StubPath"))
            if value_str is None:
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_ACTIVE_SETUP_PATH}\\{component}\\StubPath",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
