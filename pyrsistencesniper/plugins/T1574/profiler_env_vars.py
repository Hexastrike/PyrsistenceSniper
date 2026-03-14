"""T1574.012 CLR profiler environment-variable persistence plugins.

Detects COR_PROFILER and CORECLR_PROFILER environment variables set in
HKLM (system-wide) or HKU (per-user) Environment keys.  These variables
cause the .NET runtime to load an attacker-specified profiling DLL into
every managed process.
"""

from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

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


@register_plugin
class CorProfiler(PersistencePlugin):
    definition = CheckDefinition(
        id="cor_profiler",
        technique=".NET CLR Profiler Hijack",
        mitre_id="T1574.012",
        description=(
            "COR_PROFILER environment variables specify a DLL loaded by "
            "the .NET Framework CLR into every managed process. Both "
            "system-wide (HKLM) and per-user (HKU) Environment keys are "
            "checked."
        ),
        references=("https://attack.mitre.org/techniques/T1574/012/",),
    )

    def run(self) -> list[Finding]:
        return _scan_env_vars(self, _PROFILER_VARS)


@register_plugin
class CoreClrProfiler(PersistencePlugin):
    definition = CheckDefinition(
        id="coreclr_profiler",
        technique=".NET Core CLR Profiler Hijack",
        mitre_id="T1574.012",
        description=(
            "CORECLR_PROFILER environment variables specify a DLL loaded "
            "by the .NET Core/5+ runtime into every managed process. Both "
            "system-wide and per-user Environment keys are checked."
        ),
        references=("https://attack.mitre.org/techniques/T1574/012/",),
    )

    def run(self) -> list[Finding]:
        return _scan_env_vars(self, _CORECLR_VARS)


def _scan_env_vars(
    plugin: PersistencePlugin, var_names: tuple[str, ...]
) -> list[Finding]:
    findings: list[Finding] = []

    system_env_path = _SYSTEM_ENV_PATH_TEMPLATE.replace(
        "{controlset}", plugin.context.active_controlset
    )
    node = plugin._load_subtree("SYSTEM", system_env_path)
    if node is not None:
        for var in var_names:
            val = node.get(var)
            if val is not None:
                findings.append(
                    plugin._make_finding(
                        path=f"HKLM\\SYSTEM\\{system_env_path}\\{var}",
                        value=str(val),
                        access=AccessLevel.SYSTEM,
                    )
                )

    for profile in plugin.context.user_profiles:
        if profile.ntuser_path is None:
            continue
        hive = plugin.registry.open_hive(profile.ntuser_path)
        if hive is None:
            continue
        env_node = plugin.registry.load_subtree(hive, _ENV_PATH)
        if env_node is None:
            continue
        for var in var_names:
            val = env_node.get(var)
            if val is not None:
                findings.append(
                    plugin._make_finding(
                        path=f"HKU\\{profile.username}\\{_ENV_PATH}\\{var}",
                        value=str(val),
                        access=AccessLevel.USER,
                    )
                )

    return findings
