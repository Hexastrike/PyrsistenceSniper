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
    definition = CheckDefinition(
        id="cmd_autorun",
        technique="Command Processor AutoRun",
        mitre_id="T1546",
        description=(
            "The Command Processor AutoRun value executes a command every "
            "time cmd.exe launches. This provides persistence triggered "
            "by any interactive or scripted use of the command prompt."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Command Processor",
                values="AutoRun",
                scope=HiveScope.BOTH,
            ),
        ),
    )
