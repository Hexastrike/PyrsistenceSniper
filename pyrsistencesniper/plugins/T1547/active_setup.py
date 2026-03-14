from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, FilterRule, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

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
