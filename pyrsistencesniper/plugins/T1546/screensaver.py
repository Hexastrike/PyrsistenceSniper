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
    definition = CheckDefinition(
        id="screensaver",
        technique="Screensaver Hijack",
        mitre_id="T1546.002",
        description=(
            "The SCRNSAVE.EXE registry value defines the screensaver binary. "
            "Replacing it with a non-default executable provides per-user "
            "persistence triggered by idle timeout."
        ),
        references=("https://attack.mitre.org/techniques/T1546/002/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for profile, hive in self.hive_ops.iter_user_hives():
            node = self.registry.load_subtree(hive, r"Control Panel\Desktop")
            scr_val = node.get("SCRNSAVE.EXE") if node else None
            if scr_val is None:
                continue

            value_str = str(scr_val).strip()
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
