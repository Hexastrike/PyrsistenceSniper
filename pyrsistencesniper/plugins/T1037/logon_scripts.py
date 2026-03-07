from __future__ import annotations

from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class LogonScripts(PersistencePlugin):
    definition = CheckDefinition(
        id="logon_scripts",
        technique="Logon Scripts (UserInitMprLogonScript)",
        mitre_id="T1037.001",
        description=(
            "UserInitMprLogonScript runs a script at user logon before "
            "the desktop loads. This per-user Environment value is a "
            "well-known persistence vector that executes in the user's "
            "context."
        ),
        references=("https://attack.mitre.org/techniques/T1037/001/",),
        targets=(
            RegistryTarget(
                path=r"Environment",
                values="UserInitMprLogonScript",
                scope=HiveScope.HKU,
            ),
        ),
    )
