"""Detection for TypeLib COM Hijacking."""

from __future__ import annotations

import re

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import RegistryNode, registry_value_to_str
from pyrsistencesniper.core.windows import expand_env_vars
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SCRIPT_MONIKER_RE = re.compile(r"^script:", re.IGNORECASE)
_RESOURCE_INDEX_RE = re.compile(r"\\\d+$")
_PLATFORMS: tuple[str, ...] = ("win32", "win64")


def _library_file(registered_value: str, username: str) -> str:
    """Return the file a TypeLib registration points at, ready to look up on disk."""
    if _SCRIPT_MONIKER_RE.match(registered_value):
        return ""
    return expand_env_vars(_RESOURCE_INDEX_RE.sub("", registered_value), username)


@register_plugin
class TypeLibHijack(PersistencePlugin):
    """Detects TypeLib COM Hijacking persistence entries."""

    definition = CheckDefinition(
        id="typelib_hijack",
        technique="TypeLib COM Hijacking",
        mitre_id="T1546.015",
        description=(
            "A TypeLib entry under HKCU\\Software\\Classes\\TypeLib overrides the "
            "machine-wide registration, so a user can repoint a type library at a path "
            "of their choosing without administrator rights."
        ),
    )

    def run(self) -> list[Finding]:
        """Scan each user's class registrations for hijacked TypeLib entries."""
        findings: list[Finding] = []

        for profile, hive in self.context.iter_usrclass_hives():
            typelib_tree = self.registry.load_subtree(hive, "TypeLib")
            if typelib_tree is None:
                continue

            for guid, guid_node in typelib_tree.children():
                for version, version_node in guid_node.children():
                    self._collect_version(
                        profile.username, guid, version, version_node, findings
                    )

        return findings

    def _collect_version(
        self,
        username: str,
        guid: str,
        version: str,
        version_node: RegistryNode,
        findings: list[Finding],
    ) -> None:
        """Report every platform library registered under one TypeLib version."""
        for lcid, lcid_node in version_node.children():
            for platform in _PLATFORMS:
                platform_node = lcid_node.child(platform)
                if platform_node is None:
                    continue
                registered = registry_value_to_str(platform_node.get("(Default)"))
                if registered is None:
                    continue
                findings.append(
                    self._make_finding(
                        path=(
                            f"HKU\\{username}"
                            f"\\Software\\Classes\\TypeLib"
                            f"\\{guid}\\{version}\\{lcid}"
                            f"\\{platform}"
                        ),
                        value=registered,
                        access=AccessLevel.USER,
                        resolve_target=_library_file(registered, username),
                    )
                )
