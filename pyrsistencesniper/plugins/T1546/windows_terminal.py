from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from pyrsistencesniper.core.normalize import normalize_windows_path
from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

logger = logging.getLogger(__name__)


@register_plugin
class WindowsTerminal(PersistencePlugin):
    definition = CheckDefinition(
        id="windows_terminal",
        technique="Windows Terminal Custom Profiles",
        mitre_id="T1546",
        description=(
            "Windows Terminal settings.json can define profiles with "
            "custom command lines. Non-default profiles may execute "
            "arbitrary commands when a new terminal tab is opened."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for profile in self.context.user_profiles:
            settings_path = (
                f"Users\\{profile.username}\\AppData\\Local"
                "\\Packages\\Microsoft.WindowsTerminal_8wekyb3d8bbwe"
                "\\LocalState\\settings.json"
            )
            host_path = self.filesystem.resolve(settings_path)
            if not host_path.is_file():
                continue

            try:
                data = json.loads(host_path.read_text(encoding="utf-8-sig"))
            except Exception:
                logger.debug(
                    "Failed to parse Windows Terminal settings: %s",
                    host_path,
                    exc_info=True,
                )
                continue

            profiles_list = data.get("profiles", {}).get("list", [])
            for p in profiles_list:
                cmdline = p.get("commandline", "")
                if not cmdline:
                    continue
                if not self._raw:
                    cl = normalize_windows_path(cmdline).lower()
                    if cl in (
                        "cmd.exe",
                        "powershell.exe",
                        "pwsh.exe",
                        r"%systemroot%\system32\cmd.exe",
                        r"%systemroot%\system32\windowspowershell\v1.0\powershell.exe",
                    ):
                        continue

                findings.append(
                    self._make_finding(
                        path=settings_path,
                        value=cmdline,
                        access=AccessLevel.USER,
                    )
                )

        return findings
