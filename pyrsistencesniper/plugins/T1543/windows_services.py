"""Detect persistence via Windows service ImagePath and ServiceDll values."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    EventLogTime,
    Finding,
)
from pyrsistencesniper.core.registry import RegistryNode, registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SERVICES_PATH_TEMPLATE = r"{controlset}\Services"
_DRIVER_SERVICE_TYPES = frozenset({1, 2, 8})
_DRIVER_IMAGE_DIRECTORY = r"\SystemRoot\System32\drivers"


def _implied_driver_image(service_key: str, node: RegistryNode) -> str | None:
    """Name the .sys a driver service boot-loads when it declares no ImagePath."""
    raw_type = registry_value_to_str(node.get("Type"))
    if raw_type is None:
        return None
    try:
        service_type = int(raw_type, 0)
    except ValueError:
        return None
    if service_type not in _DRIVER_SERVICE_TYPES:
        return None
    return f"{service_key}.sys"


# Event 7045 carries the service's display name, not its registry key name: key
# GoogleUpdaterService149.0.7814.5 appears as "Google Updater Service
# (GoogleUpdaterService149.0.7814.5)". Every identifier the record could carry is
# offered, and the executor keeps whichever one hits.
def _installation_evidence(
    service_key: str, node: RegistryNode, image_path: str | None
) -> tuple[EventLogTime, ...]:
    """Name the 7045 installation records that could date this service."""
    descriptors = [
        EventLogTime(
            channel="System",
            event_ids=(7045,),
            match_field="ServiceName",
            match_value=service_key,
        )
    ]
    display_name = registry_value_to_str(node.get("DisplayName"))
    if display_name is not None and display_name != service_key:
        descriptors.append(
            EventLogTime(
                channel="System",
                event_ids=(7045,),
                match_field="ServiceName",
                match_value=display_name,
            )
        )
    if image_path:
        descriptors.append(
            EventLogTime(
                channel="System",
                event_ids=(7045,),
                match_field="ImagePath",
                match_value=image_path,
            )
        )
    return tuple(descriptors)


@register_plugin
class WindowsServiceImagePath(PersistencePlugin):
    """Detects Windows Service (ImagePath) persistence entries."""

    definition = CheckDefinition(
        id="windows_service_image_path",
        technique="Windows Service (ImagePath)",
        mitre_id="T1543.003",
        description=(
            "ImagePath names the executable or driver image Windows loads for a "
            "service, at boot or when the service is started."
        ),
        references=(
            "https://attack.mitre.org/techniques/T1543/003/",
            "https://docs.microsoft.com/en-us/windows/win32/services/service-programs",
        ),
    )

    def run(self) -> list[Finding]:
        """Collect ImagePath values from all services under the active ControlSet."""
        findings: list[Finding] = []

        services_path = _SERVICES_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.context.load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for service_name, node in tree.children():
            value_str = registry_value_to_str(node.get("ImagePath"))
            if value_str is None:
                driver = self._driver_without_image_path(
                    services_path, service_name, node
                )
                if driver is not None:
                    findings.append(driver)
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SYSTEM\\{services_path}\\{service_name}\\ImagePath",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                    time_evidence=_installation_evidence(service_name, node, value_str),
                )
            )

        return findings

    def _driver_without_image_path(
        self, services_path: str, service_name: str, node: RegistryNode
    ) -> Finding | None:
        """Report a driver service whose image only its own key name identifies."""
        image_name = _implied_driver_image(service_name, node)
        if image_name is None:
            return None

        return self._make_finding(
            path=f"HKLM\\SYSTEM\\{services_path}\\{service_name}",
            value=image_name,
            access=AccessLevel.SYSTEM,
            description=(
                "Driver service registered without an ImagePath value. Windows "
                f"boot-loads {_DRIVER_IMAGE_DIRECTORY}\\{image_name} by naming "
                "convention, so kernel code runs with no registry value naming it."
            ),
            resolve_target=f"{_DRIVER_IMAGE_DIRECTORY}\\{image_name}",
            time_evidence=_installation_evidence(service_name, node, None),
        )


@register_plugin
class WindowsServiceDll(PersistencePlugin):
    """Detects Windows Service (ServiceDll) persistence entries."""

    definition = CheckDefinition(
        id="windows_service_dll",
        technique="Windows Service (ServiceDll)",
        mitre_id="T1543.003",
        description=(
            "A svchost.exe-hosted service loads the DLL its ServiceDll value names "
            "when the service starts."
        ),
        references=(
            "https://attack.mitre.org/techniques/T1543/003/",
            "https://docs.microsoft.com/en-us/windows/win32/services/service-programs",
        ),
    )

    def run(self) -> list[Finding]:
        """Collect ServiceDll values from svchost-hosted service Parameters subkeys."""
        findings: list[Finding] = []

        services_path = _SERVICES_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.context.load_subtree("SYSTEM", services_path)
        if tree is None:
            return findings

        for service_name, node in tree.children():
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
                        f"\\{service_name}\\Parameters\\ServiceDll"
                    ),
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                    time_evidence=_installation_evidence(
                        service_name, node, registry_value_to_str(node.get("ImagePath"))
                    ),
                )
            )

        return findings
