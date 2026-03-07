from __future__ import annotations

from pyrsistencesniper.models.finding import AllowRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class LsaPasswordFilter(PersistencePlugin):
    definition = CheckDefinition(
        id="lsa_password_filter",
        technique="LSA Password Filter",
        mitre_id="T1556.002",
        description=(
            "LSA password filter DLLs (Notification Packages) are called "
            "on every password change. A non-default package (beyond "
            "'scecli') may capture plaintext passwords before they are "
            "hashed."
        ),
        references=("https://attack.mitre.org/techniques/T1556/002/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Lsa",
                values="Notification Packages",
                scope=HiveScope.HKLM,
            ),
        ),
        allow=(
            AllowRule(
                reason="Default Windows Security Configuration Engine",
                value_contains="scecli",
            ),
        ),
    )
