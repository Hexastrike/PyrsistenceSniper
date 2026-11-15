"""Detection for Shell Launcher Override."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class ShellLauncher(PersistencePlugin):
    """Detects Shell Launcher Override persistence entries."""

    definition = CheckDefinition(
        id="shell_launcher",
        technique="Shell Launcher Override",
        mitre_id="T1547.001",
        description=(
            "The Shell value under Policies\\System and the IniFileMapping boot\\Shell "
            "entry replace the default Windows shell, explorer.exe, with the program "
            "they name at every logon."
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Policies\Microsoft\Windows\System",
                values="Shell",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=(
                    r"SOFTWARE\Microsoft\Windows NT"
                    r"\CurrentVersion\IniFileMapping"
                    r"\system.ini\boot"
                ),
                values="Shell",
                scope=HiveScope.HKLM,
            ),
        ),
    )
