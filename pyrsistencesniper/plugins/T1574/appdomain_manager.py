from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class AppDomainManagerInjection(PersistencePlugin):
    definition = CheckDefinition(
        id="appdomain_manager",
        technique="AppDomainManager Injection",
        mitre_id="T1574.014",
        description=(
            "APPDOMAIN_MANAGER_ASM and APPDOMAIN_MANAGER_TYPE environment "
            "variables instruct the .NET CLR to load a custom "
            "AppDomainManager assembly before any .NET application executes. "
            "These variables are never set in legitimate configurations."
        ),
        references=("https://attack.mitre.org/techniques/T1574/014/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager\Environment",
                values="APPDOMAIN_MANAGER_ASM",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager\Environment",
                values="APPDOMAIN_MANAGER_TYPE",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"Environment",
                values="APPDOMAIN_MANAGER_ASM",
                scope=HiveScope.HKU,
            ),
            RegistryTarget(
                path=r"Environment",
                values="APPDOMAIN_MANAGER_TYPE",
                scope=HiveScope.HKU,
            ),
        ),
    )
