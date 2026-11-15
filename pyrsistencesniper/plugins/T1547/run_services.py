"""Detections for the Win9x-era RunServices auto-start keys."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class RunServices(PersistencePlugin):
    """Detects RunServices (Legacy) persistence entries."""

    definition = CheckDefinition(
        id="run_services",
        technique="RunServices (Legacy)",
        mitre_id="T1547.001",
        description=(
            "RunServices is a deprecated Win9x-era auto-start key, empty on a clean "
            "system."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class RunServicesOnce(PersistencePlugin):
    """Detects RunServicesOnce (Legacy) persistence entries."""

    definition = CheckDefinition(
        id="run_services_once",
        technique="RunServicesOnce (Legacy)",
        mitre_id="T1547.001",
        description=(
            "RunServicesOnce is a deprecated Win9x-era auto-start key, empty on a "
            "clean system."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                scope=HiveScope.HKLM,
            ),
        ),
    )
