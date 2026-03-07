from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_ACCESSIBILITY_TOOLS: tuple[str, ...] = (
    r"Windows\System32\sethc.exe",
    r"Windows\System32\osk.exe",
    r"Windows\System32\Narrator.exe",
    r"Windows\System32\Magnify.exe",
    r"Windows\System32\utilman.exe",
    r"Windows\System32\AtBroker.exe",
    r"Windows\System32\DisplaySwitch.exe",
)

_ATTACK_BINARIES: frozenset[str] = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "explorer.exe",
    }
)


@register_plugin
class AccessibilityTools(PersistencePlugin):
    definition = CheckDefinition(
        id="accessibility_tools",
        technique="Accessibility Features Backdoor",
        mitre_id="T1546.008",
        description=(
            "Accessibility tools (sethc.exe, osk.exe, utilman.exe, etc.) "
            "execute at the lock screen before authentication. Replacing "
            "them with cmd.exe or powershell.exe provides pre-logon "
            "SYSTEM access, typically exploited via RDP."
        ),
        references=("https://attack.mitre.org/techniques/T1546/008/",),
    )

    def run(self) -> list[Finding]:
        """Check accessibility EXEs against known binaries."""
        findings: list[Finding] = []

        attack_hashes: set[str] = set()
        for name in _ATTACK_BINARIES:
            h = self.filesystem.sha256(f"Windows\\System32\\{name}")
            if h:
                attack_hashes.add(h)

        if not attack_hashes:
            return findings

        for tool_path in _ACCESSIBILITY_TOOLS:
            tool_hash = self.filesystem.sha256(tool_path)
            if tool_hash and tool_hash in attack_hashes:
                findings.append(
                    self._make_finding(
                        path=tool_path,
                        value=f"SHA-256 matches an attack binary: {tool_hash}",
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
