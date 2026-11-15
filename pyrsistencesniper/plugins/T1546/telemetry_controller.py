"""Detection for Telemetry Controller binary and command persistence."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import RegistryNode, registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_TELEMETRY_PATH = (
    r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController"
)
_PAYLOAD_VALUES = ("Binary", "Command", "MaintenanceCommand")


@register_plugin
class TelemetryController(PersistencePlugin):
    """Detects Telemetry Controller Command persistence entries."""

    definition = CheckDefinition(
        id="telemetry_controller",
        technique="Telemetry Controller Command",
        mitre_id="T1546",
        description=(
            "TelemetryController subkeys under AppCompatFlags name the DLL "
            "CompatTelRunner.exe loads and the command it runs on the Microsoft "
            "Compatibility Appraiser schedule, both as SYSTEM."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every binary and command registered under TelemetryController."""
        findings: list[Finding] = []

        tree = self.context.load_subtree("SOFTWARE", _TELEMETRY_PATH)
        if tree is None:
            return findings

        findings.extend(self._payloads_in(tree, _TELEMETRY_PATH))
        for controller, node in tree.children():
            findings.extend(self._payloads_in(node, f"{_TELEMETRY_PATH}\\{controller}"))

        return findings

    def _payloads_in(self, node: RegistryNode, key_path: str) -> list[Finding]:
        """Return a finding for each payload value carried directly by one key."""
        findings: list[Finding] = []
        for value_name in _PAYLOAD_VALUES:
            value_str = registry_value_to_str(node.get(value_name))
            if value_str is None:
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{key_path}\\{value_name}",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )
        return findings
