"""T1574.012 CLR profiler environment-variable persistence plugins."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_PROFILER_VARS: tuple[str, ...] = (
    "COR_PROFILER",
    "COR_PROFILER_PATH",
    "COR_ENABLE_PROFILING",
)

_CORECLR_VARS: tuple[str, ...] = (
    "CORECLR_PROFILER",
    "CORECLR_PROFILER_PATH",
    "CORECLR_ENABLE_PROFILING",
)

_ENV_PATH = r"Environment"
_SYSTEM_ENV_PATH_TEMPLATE = r"{controlset}\Control\Session Manager\Environment"
_SERVICES_PATH_TEMPLATE = r"{controlset}\Services"
_SERVICE_ENV_VALUE = "Environment"


@register_plugin
class CorProfiler(PersistencePlugin):
    """Detects .NET CLR Profiler Hijack persistence entries."""

    definition = CheckDefinition(
        id="cor_profiler",
        technique=".NET CLR Profiler Hijack",
        mitre_id="T1574.012",
        description=(
            "COR_PROFILER environment variables name a profiler DLL the .NET Framework "
            "CLR loads into every managed process that inherits them. They can be set "
            "machine-wide, per user, or per service, the documented way to attach a "
            "profiler to a single service such as W3SVC."
        ),
        references=("https://attack.mitre.org/techniques/T1574/012/",),
    )

    def run(self) -> list[Finding]:
        """Report COR_PROFILER variables set for the machine, a service or a user."""
        return _scan_env_vars(self, _PROFILER_VARS)


@register_plugin
class CoreClrProfiler(PersistencePlugin):
    """Detects .NET Core CLR Profiler Hijack persistence entries."""

    definition = CheckDefinition(
        id="coreclr_profiler",
        technique=".NET Core CLR Profiler Hijack",
        mitre_id="T1574.012",
        description=(
            "CORECLR_PROFILER environment variables name a profiler DLL the .NET "
            "Core/5+ runtime loads into every managed process that inherits them, set "
            "machine-wide, per user or per service."
        ),
        references=("https://attack.mitre.org/techniques/T1574/012/",),
    )

    def run(self) -> list[Finding]:
        """Report CORECLR_PROFILER variables set for machine, service or user."""
        return _scan_env_vars(self, _CORECLR_VARS)


def _scan_env_vars(
    plugin: PersistencePlugin, var_names: tuple[str, ...]
) -> list[Finding]:
    """Report the named variables from the machine, service and user Environment."""
    findings: list[Finding] = []

    system_env_path = _SYSTEM_ENV_PATH_TEMPLATE.replace(
        "{controlset}", plugin.context.active_controlset
    )
    node = plugin.context.load_subtree("SYSTEM", system_env_path)
    if node is not None:
        for var_name in var_names:
            raw_value = node.get(var_name)
            if raw_value is not None:
                findings.append(
                    plugin._make_finding(
                        path=f"HKLM\\SYSTEM\\{system_env_path}\\{var_name}",
                        value=str(raw_value),
                        access=AccessLevel.SYSTEM,
                    )
                )

    findings.extend(_scan_service_env_vars(plugin, var_names))

    for profile in plugin.context.user_profiles:
        if profile.ntuser_path is None:
            continue
        hive = plugin.registry.open_hive(profile.ntuser_path)
        if hive is None:
            continue
        env_node = plugin.registry.load_subtree(hive, _ENV_PATH)
        if env_node is None:
            continue
        for var_name in var_names:
            raw_value = env_node.get(var_name)
            if raw_value is not None:
                findings.append(
                    plugin._make_finding(
                        path=f"HKU\\{profile.username}\\{_ENV_PATH}\\{var_name}",
                        value=str(raw_value),
                        access=AccessLevel.USER,
                    )
                )

    return findings


def _environment_assignments(raw_value: object) -> dict[str, str]:
    """Parse a service's REG_MULTI_SZ Environment block into NAME=VALUE pairs."""
    entries = raw_value if isinstance(raw_value, list) else [raw_value]
    assignments: dict[str, str] = {}
    for entry in entries:
        if entry is None:
            continue
        name, separator, value = str(entry).partition("=")
        if not separator or not name.strip() or not value.strip():
            continue
        assignments.setdefault(name.strip().casefold(), value.strip())
    return assignments


def _scan_service_env_vars(
    plugin: PersistencePlugin, var_names: tuple[str, ...]
) -> list[Finding]:
    """Report profiler variables the SCM injects into a single service's process."""
    services_path = _SERVICES_PATH_TEMPLATE.replace(
        "{controlset}", plugin.context.active_controlset
    )
    tree = plugin.context.load_subtree("SYSTEM", services_path)
    if tree is None:
        return []

    findings: list[Finding] = []
    for service_name, service_node in tree.children():
        assignments = _environment_assignments(service_node.get(_SERVICE_ENV_VALUE))
        if not assignments:
            continue
        for var_name in var_names:
            value = assignments.get(var_name.casefold())
            if value is None:
                continue
            findings.append(
                plugin._make_finding(
                    path=(
                        f"HKLM\\SYSTEM\\{services_path}\\{service_name}"
                        f"\\{_SERVICE_ENV_VALUE}\\{var_name}"
                    ),
                    value=value,
                    access=AccessLevel.SYSTEM,
                )
            )
    return findings
