"""Detect persistence via service FailureCommand values in the registry."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class ServiceFailureCommand(PersistencePlugin):
    """Detects Service Failure Command persistence entries."""

    definition = CheckDefinition(
        id="service_failure_command",
        technique="Service Failure Command",
        mitre_id="T1543.003",
        description=(
            "The FailureCommand value names a program the service control "
            "manager runs when the service fails, so a crash triggers it."
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services",
                values="FailureCommand",
                recurse=True,
                scope=HiveScope.HKLM,
            ),
        ),
    )
