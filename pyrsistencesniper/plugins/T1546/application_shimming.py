"""Detection for Application Shimming (T1546.011)."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_APPCOMPAT = r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
_CUSTOM_PATH = rf"{_APPCOMPAT}\Custom"
_SDB_SUFFIX = ".sdb"


@register_plugin
class InstalledShimDatabase(PersistencePlugin):
    """Detects custom shim databases registered under InstalledSDB."""

    definition = CheckDefinition(
        id="installed_sdb",
        technique="Application Shimming",
        mitre_id="T1546.011",
        description=(
            "InstalledSDB registers a custom application compatibility database. "
            "A shim database can inject a DLL or redirect execution whenever the "
            "shimmed program starts. Windows ships its shims inside the system "
            "database, so an entry here is always a database someone installed."
        ),
        targets=(
            RegistryTarget(
                path=rf"SOFTWARE\{_APPCOMPAT}\InstalledSDB",
                values="DatabasePath",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )


@register_plugin
class CustomShimmedExecutables(PersistencePlugin):
    """Detects executables bound to a custom shim database under AppCompatFlags."""

    definition = CheckDefinition(
        id="shim_custom",
        technique="Application Shimming",
        mitre_id="T1546.011",
        description=(
            "AppCompatFlags\\Custom binds an executable name to one or more custom "
            "shim databases. Each value name is the .sdb that runs when that "
            "executable starts, so this key names what a custom shim targets."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every executable bound to a custom shim database."""
        findings: list[Finding] = []

        tree = self.context.load_subtree("SOFTWARE", _CUSTOM_PATH)
        if tree is None:
            return findings

        for executable, node in tree.children():
            for value_name, _data in node.values():
                if not value_name.lower().endswith(_SDB_SUFFIX):
                    continue
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\SOFTWARE\\{_CUSTOM_PATH}\\{executable}",
                        value=f"{executable} -> {value_name}",
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
