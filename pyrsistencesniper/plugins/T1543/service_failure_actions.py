"""Detect persistence via service FailureCommand values in the registry."""

from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, FilterRule, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

_SERVICES_PATH_TEMPLATE = r"{controlset}\Services"


@register_plugin
class ServiceFailureCommand(PersistencePlugin):
    definition = CheckDefinition(
        id="service_failure_command",
        technique="Service Failure Command",
        mitre_id="T1543.003",
        description=(
            "The FailureCommand value specifies a program to run when a "
            "service fails. Abuse provides persistence triggered by service "
            "crashes."
        ),
        references=("https://attack.mitre.org/techniques/T1543/003/",),
        allow=(
            FilterRule(
                reason="No failure command configured", value_matches=r"^not used$"
            ),
        ),
    )

    def run(self) -> list[Finding]:
        """Collect FailureCommand values from services under the active ControlSet."""
        findings: list[Finding] = []

        services_path = _SERVICES_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self._load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for svc_name, node in tree.children():
            value_str = self._to_str(node.get("FailureCommand"))
            if value_str is None:
                continue

            findings.append(
                self._make_finding(
                    path=(f"HKLM\\SYSTEM\\{services_path}\\{svc_name}\\FailureCommand"),
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
