"""Base class and shared helpers for persistence detection plugins."""

from __future__ import annotations

from collections.abc import Iterator
from typing import ClassVar

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.forensics.registry import RegistryNode
from pyrsistencesniper.models.check import (
    CheckDefinition,
    HiveProtocol,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.models.finding import (
    AccessLevel,
    Finding,
    UserProfile,
)
from pyrsistencesniper.resolution.normalize import normalize_windows_path

__all__ = [
    "CheckDefinition",
    "HiveProtocol",
    "HiveScope",
    "PersistencePlugin",
    "RegistryTarget",
]


class PersistencePlugin:
    """Base class for persistence detection plugins.

    Subclasses provide a CheckDefinition and either rely on the built-in
    declarative engine or override run() for custom detection logic.
    """

    definition: ClassVar[CheckDefinition]

    def __init__(
        self, context: AnalysisContext, *, include_defaults: bool = False
    ) -> None:
        self.context = context
        self.registry = context.registry
        self.filesystem = context.filesystem
        self.profile = context.profile
        self._include_defaults = include_defaults

    def _open_hive(self, hive_name: str) -> HiveProtocol | None:
        """Resolve and open a registry hive by name. Returns None on failure."""
        hive_path = self.context.hive_path(hive_name)
        if hive_path is None:
            return None
        return self.registry.open_hive(hive_path)

    def _load_subtree(self, hive_name: str, key_path: str) -> RegistryNode | None:
        """Open a hive and return a RegistryNode for the given key path."""
        hive = self._open_hive(hive_name)
        if hive is None:
            return None
        return self.registry.load_subtree(hive, key_path)

    def _make_finding(
        self,
        path: str,
        value: str,
        access: AccessLevel,
        *,
        description: str = "",
    ) -> Finding:
        """Create a Finding populated with this plugin's definition metadata."""
        check = self.definition
        return Finding(
            path=path,
            value=value,
            technique=check.technique,
            mitre_id=check.mitre_id,
            description=description or check.description,
            access_gained=access,
            hostname=self.context.hostname,
            check_id=check.id,
            references=check.references,
        )

    @staticmethod
    def _to_str(raw_value: object) -> str | None:
        """Convert a registry value to a stripped string; return None if blank."""
        if raw_value is None:
            return None
        stripped_text = str(raw_value).strip()
        return stripped_text if stripped_text else None

    def _iter_user_hives(self) -> Iterator[tuple[UserProfile, HiveProtocol]]:
        """Iterate over user profiles, yielding each with its opened NTUSER hive."""
        for user_profile in self.context.user_profiles:
            if user_profile.ntuser_path is None:
                continue
            hive = self.registry.open_hive(user_profile.ntuser_path)
            if hive is not None:
                yield user_profile, hive

    def _resolve_clsid_default(self, hive: HiveProtocol, subpath: str) -> str:
        """Return the (Default) value at a registry subpath, or empty string."""
        node = self.registry.load_subtree(hive, subpath)
        if node is None:
            return ""
        default_value = node.get("(Default)")
        return str(default_value) if default_value else ""

    def _resolve_clsid_inproc(self, hive: HiveProtocol, clsid: str) -> str:
        """Look up a CLSID's InprocServer32 DLL path, or return empty string."""
        if not clsid.startswith("{"):
            return ""
        return self._resolve_clsid_default(
            hive, f"Classes\\CLSID\\{clsid}\\InprocServer32"
        )

    def run(self) -> list[Finding]:
        """Execute the check. Override in subclasses for custom detection.

        Filtering convention -- plugins filter at two levels:

        * **In run()**: reject values that are not valid findings (garbage
          data, non-executable flags, wrong value types).  These are data
          quality checks and apply even when ``--raw`` is used.
        * **FilterRule (allow/block)**: suppress values that *are* valid
          persistence entries but are known-good defaults (e.g.
          ``explorer.exe`` for ``winlogon_shell``).  These are policy
          decisions and are bypassed by ``--min-severity info``.
        """
        return self._execute_definition()

    def _execute_definition(self) -> list[Finding]:
        """Walk all declared targets and emit findings."""
        findings: list[Finding] = []
        for target in self.definition.targets:
            for hive, key_path, canonical_prefix in self._iter_hive_contexts(target):
                self._collect_findings_from_node(
                    hive, key_path, canonical_prefix, target.values, findings
                )
        return findings

    def _collect_findings_from_node(
        self,
        hive: HiveProtocol,
        key_path: str,
        canonical_prefix: str,
        values_selector: str,
        findings: list[Finding],
    ) -> None:
        """Read registry values from a node and append findings."""
        for name, raw_value in self._read_values(hive, key_path, values_selector):
            for value_string in self._flatten_registry_value(raw_value):
                registry_path = self._build_registry_path(
                    canonical_prefix, key_path, name
                )
                access_level = (
                    AccessLevel.SYSTEM
                    if canonical_prefix.startswith("HKLM")
                    else AccessLevel.USER
                )
                findings.append(
                    self._make_finding(
                        path=registry_path,
                        value=value_string,
                        access=access_level,
                    )
                )

    @staticmethod
    def _flatten_registry_value(raw_value: object) -> list[str]:
        """Convert a raw registry value to a list of non-blank strings.

        REG_MULTI_SZ values arrive as lists; each non-blank element
        becomes its own entry. Other types become a single-element list.
        """
        if isinstance(raw_value, list):
            return [
                str(element)
                for element in raw_value
                if element is not None and str(element).strip().strip('"')
            ]
        text = str(raw_value) if raw_value is not None else ""
        if not text.strip():
            return []
        return [text]

    @staticmethod
    def _build_registry_path(
        canonical_prefix: str, key_path: str, value_name: str
    ) -> str:
        """Construct a human-readable registry path."""
        registry_path = (
            f"{canonical_prefix}\\{key_path}" if key_path else canonical_prefix
        )
        if value_name and value_name != "(Default)":
            registry_path = f"{registry_path}\\{value_name}"
        return registry_path

    def _iter_hive_contexts(
        self, target: RegistryTarget
    ) -> Iterator[tuple[HiveProtocol, str, str]]:
        """Yield (hive_object, key_path, canonical_prefix) for each applicable hive."""
        scope = target.scope

        if scope in (HiveScope.HKLM, HiveScope.BOTH):
            normalized = (
                normalize_windows_path(target.path).strip("\\") if target.path else ""
            )
            parts = normalized.split("\\", 1) if normalized else [""]
            hive_name = parts[0] if parts else ""
            key_path = parts[1] if len(parts) > 1 else ""

            if "{controlset}" in key_path:
                key_path = key_path.replace(
                    "{controlset}", self.context.active_controlset
                )

            hive_path = self.context.hive_path(hive_name)
            if hive_path is not None:
                hive = self.registry.open_hive(hive_path)
                if hive is not None:
                    yield hive, key_path, f"HKLM\\{hive_name}"

        if scope in (HiveScope.HKU, HiveScope.BOTH):
            for user_profile in self.context.user_profiles:
                if user_profile.ntuser_path is None:
                    continue
                hive = self.registry.open_hive(user_profile.ntuser_path)
                if hive is None:
                    continue
                yield hive, target.path, f"HKU\\{user_profile.username}"

    def _read_values(
        self, hive: HiveProtocol, key_path: str, values_selector: str
    ) -> Iterator[tuple[str, object]]:
        """Yield (name, value) pairs from the registry node at key_path."""
        node = self.registry.load_subtree(hive, key_path)
        if node is None:
            return
        if values_selector == "*":
            yield from node.values()
        else:
            registry_value = node.get(values_selector)
            if registry_value is not None:
                yield values_selector, registry_value
