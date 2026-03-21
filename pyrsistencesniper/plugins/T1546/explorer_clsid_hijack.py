from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class ExplorerClsidHijack(PersistencePlugin):
    definition = CheckDefinition(
        id="explorer_clsid_hijack",
        technique="Explorer Desktop CLSID Hijack",
        mitre_id="T1546.015",
        description=(
            "Commonly hijacked Explorer CLSIDs (Desktop, My Computer, "
            "My Documents) shell command handlers are checked. Hijacking "
            "these command subkeys executes arbitrary code when a user "
            "opens the corresponding Explorer namespace."
        ),
        references=("https://attack.mitre.org/techniques/T1546/015/",),
        targets=(
            RegistryTarget(
                path=(
                    r"SOFTWARE\Classes\CLSID"
                    r"\{52205fd8-5dfb-447d-801a-d0b52f2e83e1}"
                    r"\shell\opennewwindow\command"
                ),
                values="(Default)",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=(
                    r"SOFTWARE\Classes\CLSID"
                    r"\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
                    r"\shell\open\command"
                ),
                values="(Default)",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=(
                    r"SOFTWARE\Classes\CLSID"
                    r"\{450D8FBA-AD25-11D0-98A8-0800361B1103}"
                    r"\shell\open\command"
                ),
                values="(Default)",
                scope=HiveScope.BOTH,
            ),
        ),
    )
