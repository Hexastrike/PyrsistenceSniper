"""Detection for Time Providers."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class TimeProviders(PersistencePlugin):
    """Detects Time Providers persistence entries."""

    definition = CheckDefinition(
        id="time_providers",
        technique="Time Providers",
        mitre_id="T1547.003",
        description=(
            "Time provider DLLs are loaded by the W32Time service at startup. The "
            "defaults are NtpClient, NtpServer and VMICTimeProvider (Hyper-V)."
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\W32Time\TimeProviders",
                values="DllName",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )
