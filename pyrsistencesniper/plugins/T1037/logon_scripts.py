"""Detect user logon script persistence via UserInitMprLogonScript (T1037.001).

The UserInitMprLogonScript value in each user's Environment key runs a
script at logon before the desktop loads, providing per-user persistence
that executes in the user's security context.
"""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class LogonScripts(PersistencePlugin):
    """Check for UserInitMprLogonScript persistence in per-user Environment keys."""

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
