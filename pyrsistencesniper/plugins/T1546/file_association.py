from __future__ import annotations

from pathlib import PureWindowsPath

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FilterRule,
    Finding,
    HiveProtocol,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.core.winutil import SCRIPT_LAUNCHERS, is_lolbin
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


def _is_suspicious_handler(cmdline: str) -> bool:
    """Return True if the handler command invokes a LOLBin or interpreter."""
    s = cmdline.strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        exe = s[1:end] if end != -1 else s[1:]
    else:
        exe = s.split()[0] if s else ""
    if not exe:
        return False
    name = PureWindowsPath(exe).name.lower()
    return name.removesuffix(".exe") in SCRIPT_LAUNCHERS or is_lolbin(exe)


_HIGH_RISK_EXTENSIONS: tuple[str, ...] = (
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".html",
    ".htm",
    ".js",
    ".vbs",
    ".hta",
    ".exe",
    ".bat",
    ".cmd",
    ".ps1",
)


@register_plugin
class FileAssociationHijack(PersistencePlugin):
    definition = CheckDefinition(
        id="file_association_hijack",
        technique="File Association Hijacking",
        mitre_id="T1546.001",
        description=(
            "Per-user and system-wide file association command handlers "
            "for high-risk extensions (.txt, .pdf, .doc, .js, .exe, etc.) "
            "are checked. Both direct extension handlers and progid-"
            "redirected handlers are examined."
        ),
        references=("https://attack.mitre.org/techniques/T1546/001/",),
        allow=(
            FilterRule(
                reason="Standard system handler",
                signer="Microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self.hive_ops.open_hive("SOFTWARE")
        if hive is not None:
            self._check_hive(
                hive, "Classes", "HKLM\\SOFTWARE", AccessLevel.SYSTEM, findings
            )

        for profile, uhive in self.hive_ops.iter_usrclass_hives():
            self._check_hive(
                uhive,
                "Software\\Classes",
                f"HKU\\{profile.username}",
                AccessLevel.USER,
                findings,
            )

        return findings

    def _check_hive(
        self,
        hive: HiveProtocol,
        classes_prefix: str,
        path_prefix: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        for ext in _HIGH_RISK_EXTENSIONS:
            # Direct extension handler
            cmd_path = f"{classes_prefix}\\{ext}\\shell\\open\\command"
            node = self.registry.load_subtree(hive, cmd_path)
            if node is not None:
                default_val = registry_value_to_str(node.get("(Default)"))
                if default_val is not None and _is_suspicious_handler(default_val):
                    findings.append(
                        self._make_finding(
                            path=f"{path_prefix}\\{cmd_path}",
                            value=default_val,
                            access=access,
                        )
                    )

            # Progid indirection: .ext -> progid -> progid\shell\open\command
            ext_node = self.registry.load_subtree(hive, f"{classes_prefix}\\{ext}")
            if ext_node is None:
                continue
            progid = registry_value_to_str(ext_node.get("(Default)"))
            if progid is None or "\\" in progid or progid.startswith('"'):
                continue
            progid_cmd = f"{classes_prefix}\\{progid}\\shell\\open\\command"
            progid_node = self.registry.load_subtree(hive, progid_cmd)
            if progid_node is None:
                continue
            progid_val = registry_value_to_str(progid_node.get("(Default)"))
            if progid_val is not None and _is_suspicious_handler(progid_val):
                findings.append(
                    self._make_finding(
                        path=f"{path_prefix}\\{progid_cmd}",
                        value=progid_val,
                        access=access,
                    )
                )
