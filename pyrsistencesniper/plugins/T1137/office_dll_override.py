"""Detect Office internal DLL override persistence."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_OVERRIDE_VALUES: tuple[str, ...] = (
    "WwlibtDll",
    "PPCoreTDLL",
)

_OFFICE_APPS: tuple[str, ...] = ("Word", "PowerPoint")

_OFFICE_VERSIONS: tuple[str, ...] = ("", "14.0", "15.0", "16.0")

_CLICK_TO_RUN_MACHINE = r"Microsoft\Office\ClickToRun\REGISTRY\MACHINE"

_MACHINE_OFFICE_ROOTS: tuple[str, ...] = (
    r"Microsoft\Office",
    rf"{_CLICK_TO_RUN_MACHINE}\Software\Microsoft\Office",
)

_USER_OFFICE_ROOT = r"Software\Microsoft\Office"


@register_plugin
class OfficeDllOverride(PersistencePlugin):
    """Detects Office DLL Override persistence entries."""

    definition = CheckDefinition(
        id="office_dll_override",
        technique="Office DLL Override",
        mitre_id="T1137",
        description=(
            "WwlibtDll (Word) and PPCoreTDLL (PowerPoint) are registry overrides "
            "naming a DLL the application loads when it starts. The per-user key needs "
            "no administrator rights."
        ),
        references=("https://attack.mitre.org/techniques/T1137/",),
    )

    def run(self) -> list[Finding]:
        """Report every Office internal DLL override the hives declare."""
        findings: list[Finding] = []

        machine_hive = self.context.open_hive_by_name("SOFTWARE")
        if machine_hive is not None:
            for office_root in _MACHINE_OFFICE_ROOTS:
                self._scan_office_root(
                    machine_hive,
                    office_root,
                    r"HKLM\SOFTWARE",
                    AccessLevel.SYSTEM,
                    findings,
                )

        for profile, user_hive in self.context.iter_user_hives():
            self._scan_office_root(
                user_hive,
                _USER_OFFICE_ROOT,
                f"HKU\\{profile.username}",
                AccessLevel.USER,
                findings,
            )

        return findings

    def _scan_office_root(
        self,
        hive: HiveProtocol,
        office_root: str,
        path_prefix: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        """Read each application key on its own, never the Office subtree above it."""
        for version in _OFFICE_VERSIONS:
            version_segment = f"{version}\\" if version else ""
            for app in _OFFICE_APPS:
                app_path = f"{office_root}\\{version_segment}{app}"
                app_node = self.registry.load_subtree(hive, app_path)
                if app_node is None:
                    continue
                for value_name in _OVERRIDE_VALUES:
                    raw_value = app_node.get(value_name)
                    if raw_value is None:
                        continue
                    findings.append(
                        self._make_finding(
                            path=f"{path_prefix}\\{app_path}\\{value_name}",
                            value=str(raw_value),
                            access=access,
                        )
                    )
