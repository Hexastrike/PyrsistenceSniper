"""Detection for .NET Framework COR_PROFILER Registry Key."""

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
    """Detects .NET Framework COR_PROFILER Registry Key persistence entries."""

    definition = CheckDefinition(
        id="dotnet_framework_profiler",
        technique=".NET Framework COR_PROFILER Registry Key",
        mitre_id="T1574.012",
        description=(
            "COR_PROFILER, COR_PROFILER_PATH and COR_ENABLE_PROFILING in the "
            ".NETFramework registry key make the CLR load a profiler DLL into every "
            "managed process. The per-user copy of the key needs no administrator "
            "rights."
        ),
        references=("https://attack.mitre.org/techniques/T1574/012/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="COR_PROFILER",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="COR_PROFILER_PATH",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="COR_ENABLE_PROFILING",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
        ),
    )
