"""Detect user logon script persistence via UserInitMprLogonScript (T1037.001)."""

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
            "UserInitMprLogonScript in a user's Environment key runs a "
            "script at logon, before the desktop loads, in that user's own "
            "context."
        ),
        targets=(
            RegistryTarget(
                path=r"Environment",
                values="UserInitMprLogonScript",
                scope=HiveScope.HKU,
            ),
        ),
    )
