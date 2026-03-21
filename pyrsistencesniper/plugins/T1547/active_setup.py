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

_ACTIVE_SETUP_PATH = r"Microsoft\Active Setup\Installed Components"

# StubPath values that are bare flags rather than executable commands.
_STUB_FLAGS: frozenset[str] = frozenset(
    {
        "/UserInstall",
        "U",
    }
)


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
            FilterRule(
                reason="Built-in active setup component",
                value_matches=r"\\system32\\",
                signer="microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Built-in media/IE setup",
                value_matches=r"(unregmp2|ie4uinit)\.exe",
                signer="microsoft",
            ),
            FilterRule(
                reason="Google Chrome per-user setup",
                value_matches=r"Google\\Chrome\\Application\\.*\\Installer\\chrmstp\.exe",
                signer="google",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Microsoft Edge per-user setup",
                value_matches=r"Microsoft\\Edge\\Application\\.*\\Installer\\setup\.exe",
                signer="microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self.hive_ops.load_subtree("SOFTWARE", _ACTIVE_SETUP_PATH)
        if tree is None:
            return findings

        for component, node in tree.children():
            value_str = registry_value_to_str(node.get("StubPath"))
            if value_str is None or value_str in _STUB_FLAGS:
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_ACTIVE_SETUP_PATH}\\{component}\\StubPath",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
