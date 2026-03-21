from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    FilterRule,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class PrintMonitors(PersistencePlugin):
    definition = CheckDefinition(
        id="print_monitors",
        technique="Print Monitors",
        mitre_id="T1547.010",
        description=(
            "Print monitor DLLs are loaded by the Print Spooler service "
            "(spoolsv.exe) at startup with SYSTEM privileges. Default "
            "monitors include Local Port, Standard TCP/IP Port, USB "
            "Monitor, WSD Port. Any additional monitor is suspicious."
        ),
        references=("https://attack.mitre.org/techniques/T1547/010/",),
        allow=(
            FilterRule(
                reason="Default Windows print monitor",
                value_matches=(
                    r"^(localspl|tcpmon|usbmon|WSDMon|APMon|AppMon|FXSMON"
                    r"|msonppmon)\.dll$"
                ),
                signer="microsoft",
            ),
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
    definition = CheckDefinition(
        id="print_processors",
        technique="Print Processors",
        mitre_id="T1547.012",
        description=(
            "Print processor DLLs are loaded by the Print Spooler "
            "service at startup with SYSTEM privileges. The only default "
            "print processor is winprint (winprint.dll). Both x64 and "
            "x86 architecture paths are checked."
        ),
        references=("https://attack.mitre.org/techniques/T1547/012/",),
        allow=(
            FilterRule(
                reason="Default Windows print processor",
                value_matches=r"^winprint\.dll$",
                signer="microsoft",
            ),
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
