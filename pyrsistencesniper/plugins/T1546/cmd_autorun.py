"""Detection for Command Processor AutoRun."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class CmdAutoRun(PersistencePlugin):
    """Detects Command Processor AutoRun persistence entries."""

    definition = CheckDefinition(
        id="cmd_autorun",
        technique="Command Processor AutoRun",
        mitre_id="T1546",
        description=(
            "The Command Processor AutoRun value runs a command every time cmd.exe "
            "starts, interactively or from a script."
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Command Processor",
                values="AutoRun",
                scope=HiveScope.BOTH,
            ),
        ),
    )
