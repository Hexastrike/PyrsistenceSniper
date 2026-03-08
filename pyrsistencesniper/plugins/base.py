from __future__ import annotations

from collections.abc import Iterator
from typing import ClassVar

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.forensics.registry import RegistryNode
from pyrsistencesniper.models.check import CheckDefinition, HiveScope, RegistryTarget
from pyrsistencesniper.models.finding import (
    AccessLevel,
    Finding,
    UserProfile,
)
from pyrsistencesniper.resolution.normalize import normalize_windows_path

# Opaque handle returned by RegistryHelper.open_hive(); the concrete type
# is pyregf.file but we avoid coupling to the C extension at import time.
Hive = object

# Re-export models for backward compatibility — plugins import from here
__all__ = [
    "CheckDefinition",
    "Hive",
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

    def __init__(self, context: AnalysisContext, *, raw: bool = False) -> None:
        self.context = context
        self.registry = context.registry
        self.filesystem = context.filesystem
        self.profile = context.profile
        self._raw = raw

    def _open_hive(self, hive_name: str) -> Hive | None:
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
        defn = self.definition
        return Finding(
            path=path,
            value=value,
            technique=defn.technique,
            mitre_id=defn.mitre_id,
            description=description or defn.description,
            access_gained=access,
            hostname=self.context.hostname,
            check_id=defn.id,
            references=defn.references,
        )

    @staticmethod
    def _to_str(val: object) -> str | None:
        """Convert a registry value to a stripped string; return None if blank."""
        if val is None:
            return None
        s = str(val).strip()
        return s if s else None

    def _iter_user_hives(self) -> Iterator[tuple[UserProfile, Hive]]:
        """Iterate over user profiles, yielding each with its opened NTUSER hive."""
        for profile in self.context.user_profiles:
            if profile.ntuser_path is None:
                continue
            hive = self.registry.open_hive(profile.ntuser_path)
            if hive is not None:
                yield profile, hive

    def _resolve_clsid_default(self, hive: Hive, subpath: str) -> str:
        """Return the (Default) value at a registry subpath, or empty string."""
        node = self.registry.load_subtree(hive, subpath)
        if node is None:
            return ""
        val = node.get("(Default)")
        return str(val) if val else ""

    def _resolve_clsid_inproc(self, hive: Hive, clsid: str) -> str:
        """Look up a CLSID's InprocServer32 DLL path, or return empty string."""
        if not clsid.startswith("{"):
            return ""
        return self._resolve_clsid_default(
            hive, f"Classes\\CLSID\\{clsid}\\InprocServer32"
        )

    def run(self) -> list[Finding]:
        """Execute the check. Override in subclasses for custom detection.

        Filtering convention — plugins filter at two levels:

        * **In run()**: reject values that are not valid findings (garbage
          data, non-executable flags, wrong value types).  These are data
          quality checks and apply even when ``--raw`` is used.
        * **FilterRule (allow/block)**: suppress values that *are* valid
          persistence entries but are known-good defaults (e.g.
          ``explorer.exe`` for ``winlogon_shell``).  These are policy
          decisions and are bypassed by ``--raw``.
        """
        return self._execute_definition()

    def _execute_definition(self) -> list[Finding]:
        """Walk all declared targets and emit a Finding for each registry value."""
        defn = self.definition
        findings: list[Finding] = []

        for target in defn.targets:
            for hive, key_path, canonical_prefix in self._iter_hive_contexts(target):
                for name, raw_value in self._read_values(hive, key_path, target.values):
                    # REG_MULTI_SZ values arrive as lists; flatten each
                    # non-blank element into its own finding.
                    if isinstance(raw_value, list):
                        entries = [
                            str(v)
                            for v in raw_value
                            if v is not None and str(v).strip()
                        ]
                        if not entries:
                            continue
                    else:
                        s = str(raw_value) if raw_value is not None else ""
                        if not s.strip():
                            continue
                        entries = [s]

                    for value_str in entries:
                        # Build a human-readable registry path like
                        # HKLM\SOFTWARE\...\ValueName from the canonical
                        # prefix, key path, and value name.
                        reg_path = (
                            f"{canonical_prefix}\\{key_path}"
                            if key_path
                            else canonical_prefix
                        )
                        if name and name != "(Default)":
                            reg_path = f"{reg_path}\\{name}"

                        access = (
                            AccessLevel.SYSTEM
                            if canonical_prefix.startswith("HKLM")
                            else AccessLevel.USER
                        )

                        findings.append(
                            self._make_finding(
                                path=reg_path,
                                value=value_str,
                                access=access,
                            )
                        )

        return findings

    def _iter_hive_contexts(
        self, target: RegistryTarget
    ) -> Iterator[tuple[Hive, str, str]]:
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
        self, hive: Hive, key_path: str, values_selector: str
    ) -> Iterator[tuple[str, object]]:
        """Yield (name, value) pairs from the registry node at key_path."""
        node = self.registry.load_subtree(hive, key_path)
        if node is None:
            return
        if values_selector == "*":
            yield from node.values()
        else:
            val = node.get(values_selector)
            if val is not None:
                yield values_selector, val
