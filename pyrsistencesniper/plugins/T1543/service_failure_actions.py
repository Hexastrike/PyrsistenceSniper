"""Detect persistence via service FailureCommand values in the registry."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SERVICES_PATH_TEMPLATE = r"{controlset}\Services"


@register_plugin
class ServiceFailureCommand(PersistencePlugin):
    """Detects Service Failure Command persistence entries."""

    definition = CheckDefinition(
        id="service_failure_command",
        technique="Service Failure Command",
        mitre_id="T1543.003",
        description=(
            "The FailureCommand value names a program the service control "
            "manager runs when the service fails, so a crash triggers it."
        ),
    )

    def run(self) -> list[Finding]:
        """Collect FailureCommand values from services under the active ControlSet."""
        findings: list[Finding] = []

        services_path = _SERVICES_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.context.load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for service_name, node in tree.children():
            value_str = registry_value_to_str(node.get("FailureCommand"))
            if value_str is None:
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SYSTEM\\{services_path}\\{service_name}"
                    "\\FailureCommand",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
