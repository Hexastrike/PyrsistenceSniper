"""Detect VBA monitor DLL hijack persistence."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_VBA_CLSIDS: tuple[str, ...] = (
    "{13B4E945-2B11-4B60-94A9-B6CDE52F6F93}",
    "{0002E157-0000-0000-C000-000000000046}",
)


@register_plugin
class VbaMonitors(PersistencePlugin):
    """Detects VBA Monitor DLL Hijack persistence entries."""

    definition = CheckDefinition(
        id="vba_monitors",
        technique="VBA Monitor DLL Hijack",
        mitre_id="T1137",
        description=(
            "The InprocServer32 value of a known VBA monitor CLSID names a DLL loaded "
            "whenever VBA executes, so hijacking the COM registration runs code on "
            "every Office macro."
        ),
    )

    def run(self) -> list[Finding]:
        """Report the DLL each VBA monitor CLSID registers, machine and per-user."""
        findings: list[Finding] = []

        hive = self.context.open_hive_by_name("SOFTWARE")
        if hive is not None:
            for clsid in _VBA_CLSIDS:
                vba_path = f"Classes\\CLSID\\{clsid}\\InprocServer32"
                value_str = self.context.resolve_clsid_default(hive, vba_path)
                if value_str.strip():
                    findings.append(
                        self._make_finding(
                            path=f"HKLM\\SOFTWARE\\{vba_path}",
                            value=value_str,
                            access=AccessLevel.SYSTEM,
                        )
                    )

        for profile, usrclass_hive in self.context.iter_usrclass_hives():
            for clsid in _VBA_CLSIDS:
                lookup_path = f"CLSID\\{clsid}\\InprocServer32"
                value_str = self.context.resolve_clsid_default(
                    usrclass_hive, lookup_path
                )
                if value_str.strip():
                    findings.append(
                        self._make_finding(
                            path=(
                                f"HKU\\{profile.username}"
                                f"\\Software\\Classes\\{lookup_path}"
                            ),
                            value=value_str,
                            access=AccessLevel.USER,
                        )
                    )

        return findings
