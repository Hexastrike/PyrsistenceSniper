"""Detection for Screensaver Hijack."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class Screensaver(PersistencePlugin):
    """Detects Screensaver Hijack persistence entries."""

    definition = CheckDefinition(
        id="screensaver",
        technique="Screensaver Hijack",
        mitre_id="T1546.002",
        description=(
            "The SCRNSAVE.EXE value names the screensaver binary, which runs as the "
            "user once the idle timeout expires."
        ),
    )

    def run(self) -> list[Finding]:
        """Report the screensaver binary each user profile has configured."""
        findings: list[Finding] = []

        for profile, hive in self.context.iter_user_hives():
            node = self.registry.load_subtree(hive, r"Control Panel\Desktop")
            screensaver_value = node.get("SCRNSAVE.EXE") if node else None
            if screensaver_value is None:
                continue

            value_str = str(screensaver_value).strip()
            if not value_str:
                continue

            findings.append(
                self._make_finding(
                    path=(
                        f"HKU\\{profile.username}"
                        r"\Control Panel\Desktop\SCRNSAVE.EXE"
                    ),
                    value=value_str,
                    access=AccessLevel.USER,
                )
            )

        return findings
