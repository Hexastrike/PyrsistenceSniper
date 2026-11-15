"""Detection for AppCert DLLs."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class AppCertDlls(PersistencePlugin):
    """Detects AppCert DLLs persistence entries."""

    definition = CheckDefinition(
        id="appcert_dlls",
        technique="AppCert DLLs",
        mitre_id="T1546.009",
        description=(
            "AppCertDlls are loaded into every process that calls CreateProcess and "
            "the related Win32 process-creation APIs."
        ),
        references=("https://attack.mitre.org/techniques/T1546/009/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager\AppCertDlls",
                scope=HiveScope.HKLM,
            ),
        ),
    )
