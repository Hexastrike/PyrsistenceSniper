"""Detect VBA monitor DLL hijack persistence.

The VBE7 monitor CLSID InprocServer32 value specifies a DLL loaded whenever
VBA executes.  Hijacking this COM registration provides persistence across
all Office macro execution.
"""

from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin


@register_plugin
class VbaMonitors(PersistencePlugin):
    definition = CheckDefinition(
        id="vba_monitors",
        technique="VBA Monitor DLL Hijack",
        mitre_id="T1137",
        description=(
            "The VBE7 monitor CLSID ({13B4E945-...}) InprocServer32 value "
            "specifies a DLL loaded whenever VBA executes. Hijacking this "
            "COM registration provides persistence across all Office VBA "
            "macro execution."
        ),
        references=("https://attack.mitre.org/techniques/T1137/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self._open_hive("SOFTWARE")
        if hive is None:
            return findings

        vba_path = (
            r"Classes\CLSID\{13B4E945-2B11-4B60-94A9-B6CDE52F6F93}\InprocServer32"
        )
        value_str = self._resolve_clsid_default(hive, vba_path)
        if value_str.strip():
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{vba_path}",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
