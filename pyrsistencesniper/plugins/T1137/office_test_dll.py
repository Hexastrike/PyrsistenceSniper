"""Detect Office Test DLL persistence (T1137.002)."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class OfficeTestDll(PersistencePlugin):
    """Detects Office Test DLL persistence entries."""

    definition = CheckDefinition(
        id="office_test_dll",
        technique="Office Test DLL",
        mitre_id="T1137.002",
        description=(
            "The undocumented Office Test\\Special\\Perf key names a DLL Office "
            "applications load at startup; 32-bit Office reads the WoW64 copy. Office "
            "does not create the key by default."
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Office Test\Special\Perf",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
        ),
    )
