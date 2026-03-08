from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_SYSTEM_PS_PROFILES: tuple[str, ...] = (
    r"Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
    r"Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
    r"Windows\SysWOW64\WindowsPowerShell\v1.0\profile.ps1",
    r"Windows\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
)

_USER_PS_PROFILES: tuple[str, ...] = (
    r"Documents\WindowsPowerShell\profile.ps1",
    r"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
    r"Documents\PowerShell\profile.ps1",
    r"Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
)


@register_plugin
class PowerShellProfiles(PersistencePlugin):
    definition = CheckDefinition(
        id="powershell_profiles",
        technique="PowerShell Profile",
        mitre_id="T1546.013",
        description=(
            "PowerShell profile scripts (profile.ps1, "
            "Microsoft.PowerShell_profile.ps1) execute automatically on "
            "every PowerShell session start. Both system-wide and per-user "
            "profiles for Windows PowerShell and PowerShell Core are "
            "checked."
        ),
        references=("https://attack.mitre.org/techniques/T1546/013/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for ps_path in _SYSTEM_PS_PROFILES:
            if self.filesystem.exists(ps_path):
                findings.append(
                    self._make_finding(
                        path=ps_path,
                        value=ps_path,
                        access=AccessLevel.SYSTEM,
                    )
                )

        for profile in self.context.user_profiles:
            for ps_rel in _USER_PS_PROFILES:
                full_path = f"Users\\{profile.username}\\{ps_rel}"
                if self.filesystem.exists(full_path):
                    findings.append(
                        self._make_finding(
                            path=full_path,
                            value=full_path,
                            access=AccessLevel.USER,
                        )
                    )

        return findings
