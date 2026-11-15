"""Detection for Accessibility Features."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import RegistryNode, registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_AT_KEY = r"Microsoft\Windows NT\CurrentVersion\Accessibility\ATs"
_AT_KEY_WOW64 = r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs"
_CONFIG_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Accessibility"
_CONFIG_VALUE = "Configuration"
_DEFAULT_HIVE = "DEFAULT"
_DEFAULT_USERNAME = ".DEFAULT"


@register_plugin
class AssistiveTechnology(PersistencePlugin):
    """Detects Accessibility Features persistence entries."""

    definition = CheckDefinition(
        id="assistive_technology",
        technique="Accessibility Features",
        mitre_id="T1546.008",
        description=(
            "Assistive Technology applications registered under the Accessibility ATs "
            "key start when an accessibility feature is enabled. The Configuration "
            "value lists the ATs Windows starts by itself: per user at logon, and from "
            "the DEFAULT hive on the sign-in desktop before any user authenticates."
        ),
        references=(
            "https://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/",
        ),
    )

    def run(self) -> list[Finding]:
        """Report registered ATs and every Configuration list that auto-starts one."""
        findings: list[Finding] = []
        findings.extend(
            self._scan_at_registrations("SOFTWARE", _AT_KEY, r"HKLM\SOFTWARE")
        )
        findings.extend(
            self._scan_at_registrations("SOFTWARE", _AT_KEY_WOW64, r"HKLM\SOFTWARE")
        )
        findings.extend(self._scan_user_configuration())
        findings.extend(self._scan_signin_configuration())
        return findings

    def _scan_at_registrations(
        self, hive_name: str, at_key: str, canonical_prefix: str
    ) -> list[Finding]:
        """Report every AT registered with a launchable StartExe under an ATs key."""
        findings: list[Finding] = []

        tree = self.context.load_subtree(hive_name, at_key)
        if tree is None:
            return findings

        for at_name, node in tree.children():
            start_exe = node.get("StartExe")
            if start_exe is None or isinstance(start_exe, int):
                continue

            value_str = str(start_exe).strip()
            if not value_str or value_str.isdigit():
                continue

            params = node.get("StartParams")
            if isinstance(params, str) and params.strip():
                value_str = f"{value_str} {params.strip()}"

            findings.append(
                self._make_finding(
                    path=rf"{canonical_prefix}\{at_key}\{at_name}\StartExe",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings

    def _scan_user_configuration(self) -> list[Finding]:
        """Report the ATs each user profile auto-starts at logon."""
        findings: list[Finding] = []

        for profile, hive in self.context.iter_user_hives():
            node = self.registry.load_subtree(hive, _CONFIG_KEY)
            findings.extend(
                self._configuration_findings(node, profile.username, AccessLevel.USER)
            )

        return findings

    def _scan_signin_configuration(self) -> list[Finding]:
        """Report the ATs the sign-in desktop auto-starts out of the DEFAULT hive."""
        # This list runs on the Winlogon desktop before anyone authenticates, so
        # an AT named here executes as SYSTEM without a logon of any kind.
        node = self.context.load_subtree(_DEFAULT_HIVE, _CONFIG_KEY)
        return self._configuration_findings(node, _DEFAULT_USERNAME, AccessLevel.SYSTEM)

    def _configuration_findings(
        self, node: RegistryNode | None, username: str, access: AccessLevel
    ) -> list[Finding]:
        """Split one Accessibility Configuration list into a finding per AT name."""
        findings: list[Finding] = []

        value_str = registry_value_to_str(node.get(_CONFIG_VALUE)) if node else None
        if value_str is None:
            return findings

        for raw_at_name in value_str.split(","):
            at_name = raw_at_name.strip()
            if not at_name:
                continue

            findings.append(
                self._make_finding(
                    path=rf"HKU\{username}\{_CONFIG_KEY}\{_CONFIG_VALUE}",
                    value=at_name,
                    access=access,
                )
            )

        return findings
