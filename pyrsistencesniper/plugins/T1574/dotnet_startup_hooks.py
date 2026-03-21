"""T1574.012 .NET startup-hook persistence plugin.

Detects the DOTNET_STARTUP_HOOKS environment variable set system-wide
(HKLM) or per-user (HKU), which injects assemblies into every .NET 5+
application before the Main entry point.
"""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_ENV_PATH = r"Environment"
_SYSTEM_ENV_PATH_TEMPLATE = r"{controlset}\Control\Session Manager\Environment"


@register_plugin
class DotNetStartupHooks(PersistencePlugin):
    definition = CheckDefinition(
        id="dotnet_startup_hooks",
        technique="DOTNET_STARTUP_HOOKS",
        mitre_id="T1574.012",
        description=(
            "DOTNET_STARTUP_HOOKS specifies assemblies loaded at .NET "
            "application startup before the Main entry point. Setting "
            "this system-wide provides persistent code injection across "
            "all .NET 5+ applications."
        ),
        references=("https://attack.mitre.org/techniques/T1574/012/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        system_env_path = _SYSTEM_ENV_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )

        hive = self.hive_ops.open_hive("SYSTEM")
        if hive is not None:
            node = self.registry.load_subtree(hive, system_env_path)
            if node is not None:
                val = node.get("DOTNET_STARTUP_HOOKS")
                if val is not None:
                    findings.append(
                        self._make_finding(
                            path=f"HKLM\\SYSTEM\\{system_env_path}\\DOTNET_STARTUP_HOOKS",
                            value=str(val),
                            access=AccessLevel.SYSTEM,
                        )
                    )

        for profile, hive in self.hive_ops.iter_user_hives():
            node = self.registry.load_subtree(hive, _ENV_PATH)
            if node is None:
                continue
            val = node.get("DOTNET_STARTUP_HOOKS")
            if val is not None:
                findings.append(
                    self._make_finding(
                        path=f"HKU\\{profile.username}\\{_ENV_PATH}\\DOTNET_STARTUP_HOOKS",
                        value=str(val),
                        access=AccessLevel.USER,
                    )
                )

        return findings
