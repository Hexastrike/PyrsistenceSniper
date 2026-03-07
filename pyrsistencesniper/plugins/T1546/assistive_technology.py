from __future__ import annotations

from pathlib import PureWindowsPath
from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_AT_KEY = r"Microsoft\Windows NT\CurrentVersion\Accessibility\ATs"
_AT_KEY_WOW64 = r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs"
_CONFIG_KEY = (
    r"Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration"
)

_KNOWN_AT_EXES: frozenset[str] = frozenset(
    {
        "eoaexperiences.exe",
        "livecaptions.exe",
        "magnify.exe",
        "narrator.exe",
        "osk.exe",
        "sapisvr.exe",
        "voiceaccess.exe",
    }
)

_KNOWN_AT_NAMES: frozenset[str] = frozenset(
    {
        "cursorindicator",
        "livecaptions",
        "magnifierpane",
        "narrator",
        "osk",
        "speechreco",
        "voiceaccess",
    }
)


@register_plugin
class AssistiveTechnology(PersistencePlugin):
    definition = CheckDefinition(
        id="assistive_technology",
        technique="Accessibility Features",
        mitre_id="T1546.008",
        description=(
            "Assistive Technology (AT) applications registered in the "
            "Accessibility\\ATs key may be launched when accessibility features "
            "are enabled. The per-user Configuration key lists ATs that Windows "
            "auto-launches at logon. Registering a malicious AT or adding its "
            "name to the Configuration list provides persistence triggered by "
            "accessibility shortcuts or user logon."
        ),
        references=(
            "https://attack.mitre.org/techniques/T1546/008/",
            "https://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/",
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(
            self._scan_at_registrations("SOFTWARE", _AT_KEY, "HKLM\\SOFTWARE")
        )
        findings.extend(
            self._scan_at_registrations("SOFTWARE", _AT_KEY_WOW64, "HKLM\\SOFTWARE")
        )
        findings.extend(self._scan_user_configuration())
        return findings

    def _scan_at_registrations(
        self, hive_name: str, at_key: str, canonical_prefix: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree(hive_name, at_key)
        if tree is None:
            return findings

        for at_name, node in tree.children():
            val = node.get("StartExe")
            if val is None:
                continue

            if isinstance(val, int):
                continue

            value_str = val if isinstance(val, str) else str(val)
            value_str = value_str.strip()

            if not value_str or value_str.isdigit():
                continue

            params = node.get("StartParams")
            if params is not None and isinstance(params, str) and params.strip():
                value_str = f"{value_str} {params.strip()}"

            if not self._raw:
                exe_name = PureWindowsPath(value_str.split()[0]).name.lower()
                if exe_name in _KNOWN_AT_EXES:
                    continue

            findings.append(
                self._make_finding(
                    path=f"{canonical_prefix}\\{at_key}\\{at_name}\\StartExe",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings

    def _scan_user_configuration(self) -> list[Finding]:
        findings: list[Finding] = []

        for profile, hive in self._iter_user_hives():
            node = self.registry.load_subtree(hive, _CONFIG_KEY)
            config_val = node.get("Configuration") if node else None
            if config_val is None:
                continue

            value_str = str(config_val).strip()
            if not value_str:
                continue

            for at_name in value_str.split(","):
                at_name = at_name.strip()
                if not at_name:
                    continue

                if not self._raw and at_name.lower() in _KNOWN_AT_NAMES:
                    continue

                findings.append(
                    self._make_finding(
                        path=f"HKU\\{profile.username}\\{_CONFIG_KEY}\\Configuration",
                        value=at_name,
                        access=AccessLevel.USER,
                    )
                )

        return findings
