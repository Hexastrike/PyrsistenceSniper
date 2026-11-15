"""T1574.012 .NET startup-hook persistence plugin."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_ENV_PATH = r"Environment"
_HOOKS_VALUE = "DOTNET_STARTUP_HOOKS"
_SYSTEM_ENV_PATH_TEMPLATE = r"{controlset}\Control\Session Manager\Environment"


@register_plugin
class DotNetStartupHooks(PersistencePlugin):
    """Detects DOTNET_STARTUP_HOOKS persistence entries."""

    definition = CheckDefinition(
        id="dotnet_startup_hooks",
        technique="DOTNET_STARTUP_HOOKS",
        mitre_id="T1574.012",
        description=(
            "DOTNET_STARTUP_HOOKS lists assemblies loaded at .NET application startup, "
            "before the Main entry point, in every .NET 5+ application that inherits "
            "the variable."
        ),
        references=("https://attack.mitre.org/techniques/T1574/012/",),
    )

    def run(self) -> list[Finding]:
        """Report DOTNET_STARTUP_HOOKS set machine-wide or in any user's own hive."""
        findings: list[Finding] = []
        system_env_path = _SYSTEM_ENV_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )

        hive = self.context.open_hive_by_name("SYSTEM")
        if hive is not None:
            node = self.registry.load_subtree(hive, system_env_path)
            if node is not None:
                raw_value = node.get(_HOOKS_VALUE)
                if raw_value is not None:
                    findings.append(
                        self._make_finding(
                            path=f"HKLM\\SYSTEM\\{system_env_path}\\{_HOOKS_VALUE}",
                            value=str(raw_value),
                            access=AccessLevel.SYSTEM,
                        )
                    )

        for profile, hive in self.context.iter_user_hives():
            node = self.registry.load_subtree(hive, _ENV_PATH)
            if node is None:
                continue
            raw_value = node.get(_HOOKS_VALUE)
            if raw_value is not None:
                findings.append(
                    self._make_finding(
                        path=f"HKU\\{profile.username}\\{_ENV_PATH}\\{_HOOKS_VALUE}",
                        value=str(raw_value),
                        access=AccessLevel.USER,
                    )
                )

        return findings
