from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class FontDrivers(PersistencePlugin):
    definition = CheckDefinition(
        id="font_drivers",
        technique="Font Drivers",
        mitre_id="T1547",
        description=(
            "The Font Drivers key specifies DLLs loaded by the font "
            "subsystem at boot. This is a legacy mechanism that still "
            "functions on modern Windows but is never used by legitimate "
            "software. Any entry is inherently suspicious."
        ),
        references=("https://attack.mitre.org/techniques/T1547/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers",
                scope=HiveScope.HKLM,
            ),
        ),
    )
