from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

_TELEMETRY_PATH = (
    r"Microsoft\Windows\CurrentVersion\Diagnostics"
    r"\DiagTrack\TelemetryController"
)


@register_plugin
class TelemetryController(PersistencePlugin):
    definition = CheckDefinition(
        id="telemetry_controller",
        technique="Telemetry Controller Command",
        mitre_id="T1546",
        description=(
            "TelemetryController subkeys specify executables run by the "
            "Connected User Experiences and Telemetry service (DiagTrack). "
            "Commands execute as SYSTEM on a periodic schedule, providing "
            "stealthy persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree("SOFTWARE", _TELEMETRY_PATH)
        if tree is None:
            return findings

        for controller, node in tree.children():
            value_str = self._to_str(node.get("Command"))
            if value_str is None:
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_TELEMETRY_PATH}\\{controller}\\Command",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
