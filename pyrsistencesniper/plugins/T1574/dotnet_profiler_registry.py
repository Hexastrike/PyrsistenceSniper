from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class DotNetFrameworkProfiler(PersistencePlugin):
    definition = CheckDefinition(
        id="dotnet_framework_profiler",
        technique=".NET Framework COR_PROFILER Registry Key",
        mitre_id="T1574.012",
        description=(
            "COR_PROFILER, COR_PROFILER_PATH, and COR_ENABLE_PROFILING "
            "values in the .NETFramework registry key cause the CLR to "
            "load a custom profiler DLL into every managed process. "
            "Profiling is rarely enabled in production environments."
        ),
        references=("https://attack.mitre.org/techniques/T1574/012/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="COR_PROFILER",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="COR_PROFILER_PATH",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="COR_ENABLE_PROFILING",
                scope=HiveScope.HKLM,
            ),
        ),
    )
