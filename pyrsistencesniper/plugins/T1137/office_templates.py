"""Detect persistence via Office default template files.

Normal.dotm (Word) and PERSONAL.XLSB (Excel) are loaded automatically on
application start.  Embedded macros in these templates provide persistence
that triggers every time the application opens.
"""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_TEMPLATE_FILES: tuple[str, ...] = (
    r"AppData\Roaming\Microsoft\Templates\Normal.dotm",
    r"AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB",
)


@register_plugin
class OfficeTemplates(PersistencePlugin):
    definition = CheckDefinition(
        id="office_templates",
        technique="Office Default Templates",
        mitre_id="T1137.001",
        description=(
            "Normal.dotm (Word) and PERSONAL.XLSB (Excel) load "
            "automatically on application start. Embedded macros in these "
            "default templates provide persistence that triggers every "
            "time the application opens."
        ),
        references=("https://attack.mitre.org/techniques/T1137/001/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for profile in self.context.user_profiles:
            for tpl_rel in _TEMPLATE_FILES:
                full_path = f"Users\\{profile.username}\\{tpl_rel}"
                if self.filesystem.exists(full_path):
                    findings.append(
                        self._make_finding(
                            path=full_path,
                            value=full_path,
                            access=AccessLevel.USER,
                        )
                    )

        return findings
