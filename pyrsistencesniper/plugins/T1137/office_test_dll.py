"""Detect Office Test DLL persistence (T1137.002).

The undocumented ``Office Test\\Special\\Perf`` registry key specifies a DLL
loaded by Office applications at startup.  Any value present indicates
persistence as this key has no legitimate use.
"""

from __future__ import annotations

from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class OfficeTestDll(PersistencePlugin):
    definition = CheckDefinition(
        id="office_test_dll",
        technique="Office Test DLL",
        mitre_id="T1137.002",
        description=(
            "The undocumented Office Test\\Special\\Perf key specifies a "
            "DLL loaded by Office applications at startup. Any value "
            "present indicates persistence, as this key has no legitimate "
            "use."
        ),
        references=("https://attack.mitre.org/techniques/T1137/002/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Office Test\Special\Perf",
                scope=HiveScope.BOTH,
            ),
        ),
    )
