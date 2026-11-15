"""Detection for File Association Hijacking."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
)
from pyrsistencesniper.core.registry import registry_key_join, registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

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
    """Detects File Association Hijacking persistence entries."""

    definition = CheckDefinition(
        id="file_association_hijack",
        technique="File Association Hijacking",
        mitre_id="T1546.001",
        description=(
            "The open command registered for a file extension runs whenever a file of "
            "that type is opened, either directly on the extension or through the "
            "ProgID it points to. A per-user registration overrides the system-wide "
            "one."
        ),
        references=("https://attack.mitre.org/techniques/T1546/001/",),
    )

    def run(self) -> list[Finding]:
        """Report the open command behind every high-risk extension, per hive."""
        findings: list[Finding] = []

        hive = self.context.open_hive_by_name("SOFTWARE")
        if hive is not None:
            self._check_hive(
                hive,
                "Classes",
                "HKLM\\SOFTWARE\\Classes",
                AccessLevel.SYSTEM,
                findings,
            )

        for profile, uhive in self.context.iter_usrclass_hives():
            self._check_hive(
                uhive,
                "",
                f"HKU\\{profile.username}\\Software\\Classes",
                AccessLevel.USER,
                findings,
            )

        return findings

    def _check_hive(
        self,
        hive: HiveProtocol,
        lookup_prefix: str,
        display_prefix: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        """Report the open command of every class key behind a high-risk extension."""
        by_path: dict[str, Finding] = {}
        for extension in _HIGH_RISK_EXTENSIONS:
            for key_name in self._handler_keys(hive, lookup_prefix, extension):
                finding = self._handler_finding(
                    hive, lookup_prefix, display_prefix, key_name, access
                )
                if finding is not None:
                    by_path.setdefault(finding.path, finding)
        findings.extend(by_path.values())

    def _handler_keys(
        self,
        hive: HiveProtocol,
        lookup_prefix: str,
        extension: str,
    ) -> list[str]:
        """Return the class keys whose open command governs one extension."""
        keys = [extension]
        extension_node = self.registry.load_subtree(
            hive, registry_key_join(lookup_prefix, extension)
        )
        if extension_node is None:
            return keys
        progid = registry_value_to_str(extension_node.get("(Default)"))
        if progid is None or "\\" in progid or progid.startswith('"'):
            return keys
        keys.append(progid)
        return keys

    def _handler_finding(
        self,
        hive: HiveProtocol,
        lookup_prefix: str,
        display_prefix: str,
        key_name: str,
        access: AccessLevel,
    ) -> Finding | None:
        """Return the open command registered under one class key, if there is one."""
        suffix = (key_name, "shell", "open", "command")
        node = self.registry.load_subtree(
            hive, registry_key_join(lookup_prefix, *suffix)
        )
        if node is None:
            return None
        command = registry_value_to_str(node.get("(Default)"))
        if command is None:
            return None
        return self._make_finding(
            path=registry_key_join(display_prefix, *suffix),
            value=command,
            access=access,
        )
