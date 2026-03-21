from __future__ import annotations

import logging

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FilterRule,
    Finding,
    HiveProtocol,
    HiveScope,
    KeyProtocol,
    RegistryTarget,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)

_KNOWN_PROTOCOLS: tuple[str, ...] = (
    "http",
    "https",
    "mailto",
    "ms-msdt",
    "ms-officecmd",
)


@register_plugin
class ProtocolHandlerHijack(PersistencePlugin):
    definition = CheckDefinition(
        id="protocol_handler_hijack",
        technique="Protocol Handler Hijacking",
        mitre_id="T1546.001",
        description=(
            "Protocol handler commands specify the executable invoked "
            "when a protocol URI is opened. Known high-risk protocols "
            "and all custom-registered protocol handlers with URL Protocol "
            "values are checked."
        ),
        references=("https://attack.mitre.org/techniques/T1546/001/",),
        allow=(
            FilterRule(
                reason="Default ms-msdt handler",
                value_matches=r"msdt\.exe",
                signer="microsoft",
            ),
            FilterRule(
                reason="Default Windows protocol handler",
                signer="microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self.hive_ops.open_hive("SOFTWARE")
        if hive is not None:
            self._scan_hive(
                hive, "Classes", "HKLM\\SOFTWARE", AccessLevel.SYSTEM, findings
            )

        for profile, uhive in self.hive_ops.iter_usrclass_hives():
            self._scan_hive(
                uhive,
                "Software\\Classes",
                f"HKU\\{profile.username}",
                AccessLevel.USER,
                findings,
            )

        return findings

    def _scan_hive(
        self,
        hive: HiveProtocol,
        classes_prefix: str,
        path_prefix: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        known_lower = {protocol.lower() for protocol in _KNOWN_PROTOCOLS}

        # Check known protocols explicitly
        for protocol in _KNOWN_PROTOCOLS:
            cmd_path = f"{classes_prefix}\\{protocol}\\shell\\open\\command"
            self._check_command(hive, cmd_path, path_prefix, access, findings)

        # Dynamic scan: enumerate protocol handlers via raw pyregf
        try:
            classes_key = hive.get_key_by_path(classes_prefix.replace("/", "\\"))
        except Exception:
            logger.debug(
                "Could not enumerate %s for protocol scan",
                classes_prefix,
                exc_info=True,
            )
            return
        if classes_key is None:
            return

        self._scan_custom_protocols(
            hive,
            classes_key,
            classes_prefix,
            path_prefix,
            access,
            known_lower,
            findings,
        )

    def _scan_custom_protocols(
        self,
        hive: HiveProtocol,
        classes_key: KeyProtocol,
        classes_prefix: str,
        path_prefix: str,
        access: AccessLevel,
        known_lower: set[str],
        findings: list[Finding],
    ) -> None:
        for index in range(classes_key.get_number_of_sub_keys()):
            try:
                sub_key = classes_key.get_sub_key(index)
                protocol_name = sub_key.get_name()
            except Exception:
                logger.debug("Failed to read sub key %d", index, exc_info=True)
                continue
            if protocol_name.lower() in known_lower:
                continue
            if not self._has_url_protocol(sub_key, protocol_name):
                continue
            cmd_path = f"{classes_prefix}\\{protocol_name}\\shell\\open\\command"
            self._check_command(hive, cmd_path, path_prefix, access, findings)

    @staticmethod
    def _has_url_protocol(sub_key: KeyProtocol, protocol_name: str) -> bool:
        try:
            for val_idx in range(sub_key.get_number_of_values()):
                if sub_key.get_value(val_idx).get_name().lower() == "url protocol":
                    return True
        except Exception:
            logger.debug("Failed to read value on key %s", protocol_name, exc_info=True)
        return False

    def _check_command(
        self,
        hive: HiveProtocol,
        cmd_path: str,
        path_prefix: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        node = self.registry.load_subtree(hive, cmd_path)
        if node is None:
            return
        value_str = registry_value_to_str(node.get("(Default)"))
        if value_str is not None:
            findings.append(
                self._make_finding(
                    path=f"{path_prefix}\\{cmd_path}",
                    value=value_str,
                    access=access,
                )
            )


@register_plugin
class SearchProtocolHandler(PersistencePlugin):
    definition = CheckDefinition(
        id="search_protocol_handler",
        technique="Search Protocol Handler Hijack",
        mitre_id="T1546.001",
        description=(
            "The search-ms protocol handler is normally handled by "
            "explorer.exe. Any modification to this handler is a strong "
            "indicator of search-ms protocol abuse, as documented in "
            "Follina-era attacks."
        ),
        references=("https://attack.mitre.org/techniques/T1546/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Classes\search-ms\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"Software\Classes\search-ms\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKU,
            ),
        ),
        allow=(
            FilterRule(
                reason="Default Windows search handler",
                value_matches=r"Explorer\.exe",
                signer="microsoft",
            ),
        ),
    )
