"""Detect LSA password filter DLL persistence (T1556.002)."""

from __future__ import annotations

from dataclasses import replace

from pyrsistencesniper.core.models import (
    CheckDefinition,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SYSTEM32_DIRECTORY = r"Windows\System32"
_DLL_SUFFIX = ".dll"
_PATH_CHARACTERS = frozenset({"\\", "/", ":"})


# Notification Packages holds bare module names with neither directory nor suffix
# ("scecli"); LSA appends .dll and loads them from System32. Resolution only probes
# disk for a value that already looks like a path, so without this expansion the DLL
# behind the name is never existence-, hash- or signer-checked.
def _notification_package_dll(package_name: str) -> str:
    """Return the System32 DLL that LSA loads for a notification package entry."""
    module_name = package_name.strip().strip('"')
    if not module_name or _PATH_CHARACTERS & set(module_name):
        return ""
    if not module_name.lower().endswith(_DLL_SUFFIX):
        module_name = module_name + _DLL_SUFFIX
    return _SYSTEM32_DIRECTORY + "\\" + module_name


@register_plugin
class LsaPasswordFilter(PersistencePlugin):
    """Check for non-default LSA Notification Packages in the SYSTEM hive."""

    definition = CheckDefinition(
        id="lsa_password_filter",
        technique="LSA Password Filter",
        mitre_id="T1556.002",
        description=(
            "LSA password filter DLLs (Notification Packages) are called on every "
            "password change with the new password in plaintext. The default is "
            "'scecli'."
        ),
        references=("https://attack.mitre.org/techniques/T1556/002/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Lsa",
                values="Notification Packages",
                scope=HiveScope.HKLM,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        """Point each package name at the DLL LSA loads for it, so it resolves."""
        return [
            replace(finding, resolve_target=_notification_package_dll(finding.value))
            for finding in super().run()
        ]
