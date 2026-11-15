"""Detection for Boot Verification Program."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class BootVerificationProgram(PersistencePlugin):
    """Detects Boot Verification Program persistence entries."""

    definition = CheckDefinition(
        id="boot_verification_program",
        technique="Boot Verification Program",
        mitre_id="T1547.001",
        description=(
            "The BootVerificationProgram ImagePath names a program run at every boot "
            "to confirm the boot succeeded, as SYSTEM."
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\BootVerificationProgram",
                values="ImagePath",
                scope=HiveScope.HKLM,
            ),
        ),
    )
