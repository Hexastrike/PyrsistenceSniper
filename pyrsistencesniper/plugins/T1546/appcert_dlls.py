from __future__ import annotations

from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class AppCertDlls(PersistencePlugin):
    definition = CheckDefinition(
        id="appcert_dlls",
        technique="AppCert DLLs",
        mitre_id="T1546.009",
        description=(
            "AppCertDlls are loaded into every process that calls "
            "CreateProcess and related Win32 APIs. Abuse provides code "
            "execution within the context of any spawned process."
        ),
        references=("https://attack.mitre.org/techniques/T1546/009/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager\AppCertDlls",
                scope=HiveScope.HKLM,
            ),
        ),
    )
