"""Detect persistence via Windows service ImagePath and ServiceDll values."""

from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, FilterRule, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

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
                signer="microsoft",
            ),
            FilterRule(
                reason="Built-in OS service",
                value_matches=(
                    r"(system32|syswow64|\\servicing\\"
                    r"|Microsoft\.NET\\|Windows Media Player)\\"
                ),
                signer="microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Windows Defender / ATP service",
                value_matches=r"Windows Defender",
                signer="microsoft",
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
        tree = self._load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for svc_name, node in tree.children():
            value_str = self._to_str(node.get("ImagePath"))
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
                signer="microsoft",
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
        tree = self._load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for svc_name, node in tree.children():
            params = node.child("Parameters")
            if params is None:
                continue
            value_str = self._to_str(params.get("ServiceDll"))
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
