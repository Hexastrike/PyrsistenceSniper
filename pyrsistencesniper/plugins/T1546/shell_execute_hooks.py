from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class ShellExecuteHooks(PersistencePlugin):
    definition = CheckDefinition(
        id="shell_execute_hooks",
        technique="ShellExecuteHooks",
        mitre_id="T1546",
        description=(
            "ShellExecuteHooks DLLs are loaded by Explorer.exe every "
            "time ShellExecute is called (double-clicking files, opening "
            "documents, running programs from the Start menu). The key "
            "is normally empty on modern Windows."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class SharedTaskScheduler(PersistencePlugin):
    definition = CheckDefinition(
        id="shared_task_scheduler",
        technique="SharedTaskScheduler",
        mitre_id="T1546",
        description=(
            "SharedTaskScheduler COM objects are loaded by Explorer.exe "
            "at shell startup, providing early and persistent code "
            "execution. The key is normally empty on all modern Windows "
            "installations."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
                scope=HiveScope.HKLM,
            ),
        ),
    )
