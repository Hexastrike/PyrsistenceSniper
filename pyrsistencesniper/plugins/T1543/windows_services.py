"""Detect persistence via Windows service ImagePath and ServiceDll values."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FilterRule,
    Finding,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SERVICES_PATH_TEMPLATE = r"{controlset}\Services"


@register_plugin
class WindowsServiceImagePath(PersistencePlugin):
    definition = CheckDefinition(
        id="windows_service_image_path",
        technique="Windows Service (ImagePath)",
        mitre_id="T1543.003",
        description=(
            "Windows services run executables at system start. A non-OS "
            "ImagePath may indicate a malicious or third-party service."
        ),
        references=(
            "https://attack.mitre.org/techniques/T1543/003/",
            "https://docs.microsoft.com/en-us/windows/win32/services/service-programs",
        ),
        allow=(
            FilterRule(
                reason="svchost-hosted service",
                value_matches=r"svchost\.exe\s+-k\b",
                signer="Microsoft",
            ),
            FilterRule(
                reason="Built-in OS service",
                value_matches=(
                    r"(system32|syswow64|\\servicing\\"
                    r"|Microsoft\.NET\\|Windows Media Player)\\"
                ),
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Windows Defender / ATP service",
                value_matches=r"Windows Defender",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Default Windows Installer service",
                value_matches=r"msiexec\.exe",
                signer="Microsoft",
            ),
            FilterRule(
                reason="Microsoft Edge / Edge Update service",
                value_matches=r"Microsoft\\(EdgeUpdate\\MicrosoftEdgeUpdate|Edge\\.*\\elevation_service)\.exe",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Google Chrome / Update service",
                value_matches=r"Google\\(GoogleUpdater\\.*\\updater|Chrome\\.*\\elevation_service)\.exe",
                signer="Google",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Windows TrustedInstaller",
                value_matches=r"TrustedInstaller\.exe",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Windows Subsystem for Linux service",
                value_matches=r"WSL\\wslservice\.exe",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason=".NET Framework shared hosting",
                value_matches=r"Microsoft\.NET\\.*\\SMSvcHost\.exe",
                signer="Microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        """Collect ImagePath values from all services under the active ControlSet."""
        findings: list[Finding] = []

        services_path = _SERVICES_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.hive_ops.load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for svc_name, node in tree.children():
            value_str = registry_value_to_str(node.get("ImagePath"))
            if value_str is None:
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SYSTEM\\{services_path}\\{svc_name}\\ImagePath",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings


@register_plugin
class WindowsServiceDll(PersistencePlugin):
    definition = CheckDefinition(
        id="windows_service_dll",
        technique="Windows Service (ServiceDll)",
        mitre_id="T1543.003",
        description=(
            "svchost.exe-hosted services load a ServiceDll. A non-OS DLL "
            "may indicate a malicious service DLL."
        ),
        references=(
            "https://attack.mitre.org/techniques/T1543/003/",
            "https://docs.microsoft.com/en-us/windows/win32/services/service-programs",
        ),
        allow=(
            FilterRule(
                reason="Built-in OS service DLL",
                value_matches=r"system32\\",
                signer="Microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        """Collect ServiceDll values from svchost-hosted service Parameters subkeys."""
        findings: list[Finding] = []

        services_path = _SERVICES_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.hive_ops.load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for svc_name, node in tree.children():
            params = node.child("Parameters")
            if params is None:
                continue
            value_str = registry_value_to_str(params.get("ServiceDll"))
            if value_str is None:
                continue

            findings.append(
                self._make_finding(
                    path=(
                        f"HKLM\\SYSTEM\\{services_path}"
                        f"\\{svc_name}\\Parameters\\ServiceDll"
                    ),
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
