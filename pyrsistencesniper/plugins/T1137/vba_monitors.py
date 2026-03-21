"""Detect VBA monitor DLL hijack persistence.

The VBE7 monitor CLSID InprocServer32 value specifies a DLL loaded whenever
VBA executes.  Hijacking this COM registration provides persistence across
all Office macro execution.
"""

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
    definition = CheckDefinition(
        id="vba_monitors",
        technique="VBA Monitor DLL Hijack",
        mitre_id="T1137",
        description=(
            "Known VBA monitor CLSIDs InprocServer32 values specify DLLs "
            "loaded whenever VBA executes. Hijacking these COM registrations "
            "provides persistence across all Office macro execution. Both "
            "HKLM and per-user hives are checked."
        ),
        references=("https://attack.mitre.org/techniques/T1137/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self.hive_ops.open_hive("SOFTWARE")
        if hive is not None:
            for clsid in _VBA_CLSIDS:
                vba_path = f"Classes\\CLSID\\{clsid}\\InprocServer32"
                value_str = self.hive_ops.resolve_clsid_default(hive, vba_path)
                if value_str.strip():
                    findings.append(
                        self._make_finding(
                            path=f"HKLM\\SOFTWARE\\{vba_path}",
                            value=value_str,
                            access=AccessLevel.SYSTEM,
                        )
                    )

        for profile, uhive in self.hive_ops.iter_usrclass_hives():
            for clsid in _VBA_CLSIDS:
                vba_path = f"Software\\Classes\\CLSID\\{clsid}\\InprocServer32"
                value_str = self.hive_ops.resolve_clsid_default(uhive, vba_path)
                if value_str.strip():
                    findings.append(
                        self._make_finding(
                            path=f"HKU\\{profile.username}\\{vba_path}",
                            value=value_str,
                            access=AccessLevel.USER,
                        )
                    )

        return findings
