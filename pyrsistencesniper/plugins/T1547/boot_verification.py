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
    definition = CheckDefinition(
        id="boot_verification_program",
        technique="Boot Verification Program",
        mitre_id="T1547.001",
        description=(
            "The BootVerificationProgram ImagePath specifies a program "
            "that confirms boot success. Hijacking this value provides "
            "SYSTEM-level persistence triggered on every boot."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\BootVerificationProgram",
                values="ImagePath",
                scope=HiveScope.HKLM,
            ),
        ),
    )
