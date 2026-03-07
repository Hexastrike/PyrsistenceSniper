from __future__ import annotations

from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class ExplorerClsidHijack(PersistencePlugin):
    definition = CheckDefinition(
        id="explorer_clsid_hijack",
        technique="Explorer Desktop CLSID Hijack",
        mitre_id="T1546.015",
        description=(
            "The Desktop namespace CLSID {52205fd8-...} shell command "
            "handler controls 'Open new window' in Explorer. Hijacking "
            "the command subkey executes arbitrary code when a user opens "
            "a new Explorer window."
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
        ),
    )
