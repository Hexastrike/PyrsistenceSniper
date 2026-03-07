from __future__ import annotations

import configparser
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_GP_DIR = Path("Windows") / "System32" / "GroupPolicy"
_SCRIPT_FILES: tuple[tuple[Path, str], ...] = (
    (Path("Machine") / "Scripts" / "scripts.ini", "Machine"),
    (Path("Machine") / "Scripts" / "psscripts.ini", "Machine (PowerShell)"),
    (Path("User") / "Scripts" / "scripts.ini", "User"),
    (Path("User") / "Scripts" / "psscripts.ini", "User (PowerShell)"),
)


@register_plugin
class GpScripts(PersistencePlugin):
    definition = CheckDefinition(
        id="gp_scripts",
        technique="Group Policy Scripts",
        mitre_id="T1037.001",
        description=(
            "Group Policy scripts.ini and psscripts.ini define "
            "startup/shutdown and logon/logoff scripts. Malicious CmdLine "
            "entries provide boot-level or logon-level persistence via "
            "the GP infrastructure."
        ),
        references=("https://attack.mitre.org/techniques/T1037/001/",),
    )

    def run(self) -> list[Finding]:
        """Scan Group Policy scripts.ini and psscripts.ini for CmdLine entries."""
        findings: list[Finding] = []

        gp_dir = self.filesystem.image_root / _GP_DIR
        if not gp_dir.is_dir():
            return findings

        for rel_path, scope in _SCRIPT_FILES:
            ini_path = gp_dir / rel_path
            if not ini_path.is_file():
                continue

            self._parse_ini(ini_path, rel_path, scope, findings)

        return findings

    def _parse_ini(
        self,
        ini_path: Path,
        rel_path: Path,
        scope: str,
        findings: list[Finding],
    ) -> None:
        config = configparser.ConfigParser(interpolation=None)
        for encoding in ("utf-16", "utf-8-sig", "utf-8"):
            try:
                config.read(str(ini_path), encoding=encoding)
                break
            except Exception:
                config.clear()
        else:
            return

        for section in config.sections():
            try:
                items = list(config.items(section))
            except Exception:
                continue

            mapping = {k.lower(): v for k, v in items}
            for key, value in items:
                key_lower = key.lower()
                if not key_lower.endswith("cmdline") or not value.strip():
                    continue

                idx = key_lower[: -len("cmdline")]
                params = mapping.get(f"{idx}parameters", "").strip()
                full = f"{value.strip()} {params}".strip() if params else value.strip()

                access = (
                    AccessLevel.SYSTEM
                    if scope.startswith("Machine")
                    else AccessLevel.USER
                )
                findings.append(
                    self._make_finding(
                        path=str(PureWindowsPath(_GP_DIR / rel_path)),
                        value=full,
                        access=access,
                        description=f"{self.definition.description} (scope: {scope})",
                    )
                )
