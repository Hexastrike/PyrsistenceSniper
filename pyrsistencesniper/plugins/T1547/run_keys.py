"""Detection for Registry Run Keys."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.core.registry import (
    RegistryNode,
    commands_below,
    stores_commands_in_sections,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class RunKeys(PersistencePlugin):
    """Detects Registry Run Keys persistence entries."""

    definition = CheckDefinition(
        id="run_keys",
        technique="Registry Run Keys",
        mitre_id="T1547.001",
        description=(
            "Run, RunOnce, RunEx and RunOnceEx keys, and the Policies\\Explorer\\Run "
            "override, start the listed programs at user logon."
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx",
                scope=HiveScope.HKLM,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        """Read the flat Run keys, then descend the RunEx and RunOnceEx sections."""
        findings = super().run()
        for target in self.definition.targets:
            if stores_commands_in_sections(target.path):
                findings.extend(self._section_findings(target))
        return findings

    def _section_findings(self, target: RegistryTarget) -> list[Finding]:
        """Collect the commands stored below one key's section subkeys."""
        findings: list[Finding] = []
        if target.scope in (HiveScope.HKLM, HiveScope.BOTH):
            hive_name, _, key_path = target.path.partition("\\")
            findings.extend(
                self._command_findings(
                    self.context.load_subtree(hive_name, key_path),
                    f"HKLM\\{target.path}",
                    AccessLevel.SYSTEM,
                )
            )
        if target.scope in (HiveScope.HKU, HiveScope.BOTH):
            for user_profile, hive in self.context.iter_user_hives():
                findings.extend(
                    self._command_findings(
                        self.registry.load_subtree(hive, target.path),
                        f"HKU\\{user_profile.username}\\{target.path}",
                        AccessLevel.USER,
                    )
                )
        return findings

    def _command_findings(
        self, node: RegistryNode | None, canonical_path: str, access: AccessLevel
    ) -> list[Finding]:
        """Report every command a key's section subkeys hold, at any depth."""
        return [
            self._make_finding(path=path, value=command, access=access)
            for path, command in commands_below(node, canonical_path)
        ]
