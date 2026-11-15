"""Detection for Font Drivers."""

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
    """Detects Font Drivers persistence entries."""

    definition = CheckDefinition(
        id="font_drivers",
        technique="Font Drivers",
        mitre_id="T1547",
        description=(
            "The Font Drivers key names DLLs the font subsystem loads at boot. It is a "
            "legacy mechanism that still works on modern Windows."
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers",
                scope=HiveScope.HKLM,
            ),
        ),
    )
