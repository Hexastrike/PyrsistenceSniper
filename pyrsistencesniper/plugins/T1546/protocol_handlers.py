"""Detection for Protocol Handler Hijacking and Search Protocol Handler Hijack."""

from __future__ import annotations

import logging

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
    HiveScope,
    KeyProtocol,
    RegistryTarget,
)
from pyrsistencesniper.core.registry import registry_key_join, registry_value_to_str
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
    """Detects Protocol Handler Hijacking persistence entries."""

    definition = CheckDefinition(
        id="protocol_handler_hijack",
        technique="Protocol Handler Hijacking",
        mitre_id="T1546.001",
        description=(
            "A protocol handler's open command names the executable started when a URI "
            "of that protocol is opened. A per-user class key can shadow a "
            "machine-registered protocol even without a URL Protocol value of its own."
        ),
    )

    def run(self) -> list[Finding]:
        """Report the open command of every protocol handler worth inspecting."""
        findings: list[Finding] = []
        machine_protocols: frozenset[str] = frozenset()

        hive = self.context.open_hive_by_name("SOFTWARE")
        if hive is not None:
            machine_protocols = self._scan_hive(
                hive,
                "Classes",
                "HKLM\\SOFTWARE\\Classes",
                AccessLevel.SYSTEM,
                findings,
            )

        for profile, uhive in self.context.iter_usrclass_hives():
            self._scan_hive(
                uhive,
                "",
                f"HKU\\{profile.username}\\Software\\Classes",
                AccessLevel.USER,
                findings,
                shadowed_protocols=machine_protocols,
            )

        return findings

    def _scan_hive(
        self,
        hive: HiveProtocol,
        lookup_prefix: str,
        display_prefix: str,
        access: AccessLevel,
        findings: list[Finding],
        *,
        shadowed_protocols: frozenset[str] = frozenset(),
    ) -> frozenset[str]:
        """Scan one hive's class registrations and report the protocols it registers."""
        known_lower = {protocol.lower() for protocol in _KNOWN_PROTOCOLS}

        for protocol in _KNOWN_PROTOCOLS:
            self._check_command(
                hive, lookup_prefix, display_prefix, protocol, access, findings
            )

        try:
            classes_key = hive.get_key_by_path(lookup_prefix.replace("/", "\\"))
        except Exception:
            logger.debug(
                "Could not enumerate %s for protocol scan",
                display_prefix,
                exc_info=True,
            )
            return frozenset()
        if classes_key is None:
            return frozenset()

        return self._scan_custom_protocols(
            hive,
            classes_key,
            lookup_prefix,
            display_prefix,
            access,
            known_lower,
            shadowed_protocols,
            findings,
        )

    def _scan_custom_protocols(
        self,
        hive: HiveProtocol,
        classes_key: KeyProtocol,
        lookup_prefix: str,
        display_prefix: str,
        access: AccessLevel,
        known_lower: set[str],
        shadowed_protocols: frozenset[str],
        findings: list[Finding],
    ) -> frozenset[str]:
        """Check every qualifying class key and return the ones marked URL Protocol."""
        registered: set[str] = set()
        for index in range(classes_key.get_number_of_sub_keys()):
            try:
                sub_key = classes_key.get_sub_key(index)
                protocol_name = sub_key.get_name()
            except Exception:
                logger.debug("Failed to read sub key %d", index, exc_info=True)
                continue
            name_lower = protocol_name.lower()
            if self._has_url_protocol(sub_key, protocol_name):
                registered.add(name_lower)
            elif name_lower not in shadowed_protocols:
                continue
            if name_lower in known_lower:
                continue
            self._check_command(
                hive, lookup_prefix, display_prefix, protocol_name, access, findings
            )
        return frozenset(registered)

    @staticmethod
    def _has_url_protocol(sub_key: KeyProtocol, protocol_name: str) -> bool:
        """Report whether a class key carries the URL Protocol marker value."""
        try:
            value_count = sub_key.get_number_of_values()
        except Exception:
            logger.debug(
                "Failed to read values on key %s", protocol_name, exc_info=True
            )
            return False
        for value_index in range(value_count):
            try:
                value = sub_key.get_value(value_index)
                # get_name() is None for the unnamed default value
                name = value.get_name() if value is not None else None
            except Exception:
                logger.debug(
                    "Failed to read value %d on key %s",
                    value_index,
                    protocol_name,
                    exc_info=True,
                )
                continue
            if name is not None and name.lower() == "url protocol":
                return True
        return False

    def _check_command(
        self,
        hive: HiveProtocol,
        lookup_prefix: str,
        display_prefix: str,
        protocol: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        """Record the open command one protocol registers, if it registers one."""
        suffix = (protocol, "shell", "open", "command")
        node = self.registry.load_subtree(
            hive, registry_key_join(lookup_prefix, *suffix)
        )
        if node is None:
            return
        value_str = registry_value_to_str(node.get("(Default)"))
        if value_str is not None:
            findings.append(
                self._make_finding(
                    path=registry_key_join(display_prefix, *suffix),
                    value=value_str,
                    access=access,
                )
            )


@register_plugin
class SearchProtocolHandler(PersistencePlugin):
    """Detects Search Protocol Handler Hijack persistence entries."""

    definition = CheckDefinition(
        id="search_protocol_handler",
        technique="Search Protocol Handler Hijack",
        mitre_id="T1546.001",
        description=(
            "The search-ms protocol handler names the program started when a search-ms "
            "URI is opened, normally explorer.exe."
        ),
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
    )
