"""Detections for the DLLs the Print Spooler loads at startup."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class PrintMonitors(PersistencePlugin):
    """Detects Print Monitors persistence entries."""

    definition = CheckDefinition(
        id="print_monitors",
        technique="Print Monitors",
        mitre_id="T1547.010",
        description=(
            "Print monitor DLLs are loaded by the Print Spooler service (spoolsv.exe) "
            "at startup, as SYSTEM. The default monitors include Local Port, Standard "
            "TCP/IP Port, USB Monitor and WSD Port."
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Print\Monitors",
                values="Driver",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )


@register_plugin
class PrintProcessors(PersistencePlugin):
    """Detects Print Processors persistence entries."""

    definition = CheckDefinition(
        id="print_processors",
        technique="Print Processors",
        mitre_id="T1547.012",
        description=(
            "Print processor DLLs are loaded by the Print Spooler service at startup, "
            "as SYSTEM. The only default print processor is winprint (winprint.dll)."
        ),
        targets=(
            RegistryTarget(
                path=(
                    r"SYSTEM\{controlset}\Control\Print"
                    r"\Environments\Windows x64\Print Processors"
                ),
                values="Driver",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
            RegistryTarget(
                path=(
                    r"SYSTEM\{controlset}\Control\Print\Environments"
                    r"\Windows NT x86\Print Processors"
                ),
                values="Driver",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )
