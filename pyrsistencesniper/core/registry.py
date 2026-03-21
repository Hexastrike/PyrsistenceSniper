"""Offline registry hive parsing with caching, built on pyregf."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pyregf

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
    HiveScope,
    KeyProtocol,
    RegistryTarget,
    UserProfile,
)
from pyrsistencesniper.core.winutil import normalize_windows_path

if TYPE_CHECKING:
    from pyrsistencesniper.core.context import AnalysisContext

logger = logging.getLogger(__name__)


def _pyregf_extract_data(pyregf_value: Any) -> object:  # noqa: ANN401
    """Convert a pyregf value to a native Python type (str, int, list, or bytes)."""
    value_type = pyregf_value.get_type()
    try:
        if value_type in (
            pyregf.value_types.STRING,
            pyregf.value_types.EXPANDABLE_STRING,
        ):
            return pyregf_value.get_data_as_string()
        if value_type in (
            pyregf.value_types.INTEGER_32BIT_LITTLE_ENDIAN,
            pyregf.value_types.INTEGER_64BIT_LITTLE_ENDIAN,
            pyregf.value_types.INTEGER_32BIT_BIG_ENDIAN,
        ):
            return pyregf_value.get_data_as_integer()
        if value_type == pyregf.value_types.MULTI_VALUE_STRING:
            return list(pyregf_value.get_data_as_multi_string())
    except Exception:
        logger.debug(
            "Failed to extract typed data for value type %s",
            value_type,
            exc_info=True,
        )
    data = pyregf_value.get_data()
    return data if data is not None else b""


def registry_value_to_str(raw_value: object) -> str | None:
    """Convert a registry value to a stripped string; return None if blank."""
    if raw_value is None:
        return None
    stripped_text = str(raw_value).strip()
    return stripped_text if stripped_text else None


class RegistryNode:
    """In-memory registry key with dict-based value and child lookups."""

    __slots__ = ("_children", "_values", "name")

    def __init__(
        self,
        name: str,
        values: dict[str, tuple[str, object]],
        children: dict[str, RegistryNode],
    ) -> None:
        self.name = name
        self._values = values
        self._children = children

    def get(self, value_name: str) -> object | None:
        """Return a value by name (case-insensitive)."""
        key = value_name.lower()
        if key == "(default)":
            key = ""
        entry = self._values.get(key)
        return entry[1] if entry is not None else None

    def child(self, name: str) -> RegistryNode | None:
        """Return a child subkey by name (case-insensitive), or None."""
        return self._children.get(name.lower())

    def children(self) -> Iterator[tuple[str, RegistryNode]]:
        """Yield (name, node) pairs for all child subkeys."""
        for node in self._children.values():
            yield (node.name, node)

    def values(self) -> Iterator[tuple[str, object]]:
        """Yield (name, data) pairs for all values in this key."""
        yield from self._values.values()


class RegistryHelper:
    """Offline registry hive parser built on pyregf with caching."""

    def __init__(self) -> None:
        self._hive_cache: dict[str, HiveProtocol | None] = {}
        self._subtree_cache: dict[tuple[int, str], RegistryNode | None] = {}

    def open_hive(self, path: Path) -> HiveProtocol | None:
        """Open a registry hive file, caching by resolved path."""
        key = str(path.resolve())
        if key in self._hive_cache:
            return self._hive_cache[key]
        try:
            reg_file = pyregf.file()
            reg_file.open(str(path))
            hive: HiveProtocol | None = reg_file
        except Exception:
            logger.warning("Failed to open hive: %s", path)
            logger.debug("Hive open error details:", exc_info=True)
            hive = None
        self._hive_cache[key] = hive
        return hive

    @staticmethod
    def _normalize_key_path(key_path: str) -> str:
        """Strip leading backslash for pyregf compatibility."""
        return key_path.lstrip("\\")

    def load_subtree(self, hive: HiveProtocol, key_path: str) -> RegistryNode | None:
        """Build and cache a RegistryNode tree for the given key path via DFS."""
        norm = self._normalize_key_path(key_path)
        cache_key = (id(hive), norm.lower())
        if cache_key in self._subtree_cache:
            return self._subtree_cache[cache_key]

        pyregf_key = self._resolve_key(hive, key_path)
        if pyregf_key is None:
            self._subtree_cache[cache_key] = None
            return None

        node = _materialize(pyregf_key)
        self._subtree_cache[cache_key] = node
        return node

    @staticmethod
    def _resolve_key(hive: HiveProtocol, key_path: str) -> KeyProtocol | None:
        """Resolve a key path to a pyregf key object, or None."""
        try:
            norm = RegistryHelper._normalize_key_path(key_path)
            return hive.get_key_by_path(norm)
        except Exception:
            logger.debug("Could not resolve key %s", key_path, exc_info=True)
            return None


def _materialize(key: KeyProtocol) -> RegistryNode:
    """Recursively convert a pyregf key and its children into a RegistryNode tree."""
    name: str = key.get_name()

    values: dict[str, tuple[str, object]] = {}
    for i in range(key.get_number_of_values()):
        registry_value = key.get_value(i)
        value_name: str = registry_value.get_name() or ""
        values[value_name.lower()] = (
            value_name,
            _pyregf_extract_data(registry_value),
        )

    children: dict[str, RegistryNode] = {}
    for i in range(key.get_number_of_sub_keys()):
        sub_key = key.get_sub_key(i)
        child_node = _materialize(sub_key)
        children[child_node.name.lower()] = child_node

    return RegistryNode(name, values, children)


class HiveOps:
    """High-level registry operations that wrap an AnalysisContext.

    Provides convenience methods for common registry access patterns
    used by persistence detection plugins.
    """

    def __init__(self, context: AnalysisContext) -> None:
        self._context = context
        self._registry: RegistryHelper = context.registry

    def open_hive(self, hive_name: str) -> HiveProtocol | None:
        """Resolve and open a registry hive by name. Returns None on failure."""
        hive_path = self._context.hive_path(hive_name)
        if hive_path is None:
            return None
        return self._registry.open_hive(hive_path)

    def load_subtree(self, hive_name: str, key_path: str) -> RegistryNode | None:
        """Open a hive and return a RegistryNode for the given key path."""
        hive = self.open_hive(hive_name)
        if hive is None:
            return None
        return self._registry.load_subtree(hive, key_path)

    def iter_user_hives(self) -> Iterator[tuple[UserProfile, HiveProtocol]]:
        """Iterate over user profiles, yielding each with its opened NTUSER hive."""
        for user_profile in self._context.user_profiles:
            if user_profile.ntuser_path is None:
                continue
            hive = self._registry.open_hive(user_profile.ntuser_path)
            if hive is not None:
                yield user_profile, hive

    def iter_usrclass_hives(self) -> Iterator[tuple[UserProfile, HiveProtocol]]:
        """Iterate user profiles, yielding each with its opened UsrClass.dat hive."""
        for user_profile in self._context.user_profiles:
            usrclass_path = self._context.hive_path(
                "UsrClass.dat", user_profile.username
            )
            if usrclass_path is None:
                continue
            hive = self._registry.open_hive(usrclass_path)
            if hive is not None:
                yield user_profile, hive

    def resolve_clsid_default(self, hive: HiveProtocol, subpath: str) -> str:
        """Return the (Default) value at a registry subpath, or empty string."""
        node = self._registry.load_subtree(hive, subpath)
        if node is None:
            return ""
        default_value = node.get("(Default)")
        return str(default_value) if default_value else ""

    def resolve_clsid_inproc(self, hive: HiveProtocol, clsid: str) -> str:
        """Look up a CLSID's InprocServer32 DLL path, or return empty string."""
        if not clsid.startswith("{"):
            return ""
        return self.resolve_clsid_default(
            hive, f"Classes\\CLSID\\{clsid}\\InprocServer32"
        )


# ---------------------------------------------------------------------------
# Declarative check engine (absorbed from plugins/engine.py)
# ---------------------------------------------------------------------------


def execute_definition(
    definition: CheckDefinition,
    registry: RegistryHelper,
    hive_path_fn: Callable[..., Path | None],
    active_controlset: str,
    user_profiles: list[UserProfile],
    make_finding: Callable[..., Finding],
) -> list[Finding]:
    """Walk all declared targets and emit findings.

    This is the main entry point for the declarative check engine.

    Parameters
    ----------
    definition:
        The check definition whose targets will be iterated.
    registry:
        Registry helper for opening hives and loading subtrees.
    hive_path_fn:
        Callable that resolves a hive name to a filesystem Path (or None).
        Typically ``context.hive_path``.
    active_controlset:
        The active ControlSet name (e.g. ``"ControlSet001"``).
    user_profiles:
        List of user profiles to iterate for HKU-scoped targets.
    make_finding:
        Callable that creates a Finding from path, value, and access level.
        Typically ``plugin._make_finding``.
    """
    findings: list[Finding] = []
    for target in definition.targets:
        for hive, key_path, canonical_prefix in _iter_hive_contexts(
            target, registry, hive_path_fn, active_controlset, user_profiles
        ):
            if target.recurse:
                _collect_findings_from_children(
                    registry,
                    hive,
                    key_path,
                    canonical_prefix,
                    target.values,
                    findings,
                    make_finding,
                )
            else:
                _collect_findings_from_node(
                    registry,
                    hive,
                    key_path,
                    canonical_prefix,
                    target.values,
                    findings,
                    make_finding,
                )
    return findings


def _iter_hive_contexts(
    target: RegistryTarget,
    registry: RegistryHelper,
    hive_path_fn: Callable[..., Path | None],
    active_controlset: str,
    user_profiles: list[UserProfile],
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
            key_path = key_path.replace("{controlset}", active_controlset)

        hive_path = hive_path_fn(hive_name)
        if hive_path is not None:
            hive = registry.open_hive(hive_path)
            if hive is not None:
                yield hive, key_path, f"HKLM\\{hive_name}"

    if scope in (HiveScope.HKU, HiveScope.BOTH):
        for user_profile in user_profiles:
            if user_profile.ntuser_path is None:
                continue
            hive = registry.open_hive(user_profile.ntuser_path)
            if hive is None:
                continue
            yield hive, target.path, f"HKU\\{user_profile.username}"


def _collect_findings_from_node(
    registry: RegistryHelper,
    hive: HiveProtocol,
    key_path: str,
    canonical_prefix: str,
    values_selector: str,
    findings: list[Finding],
    make_finding: Callable[..., Finding],
) -> None:
    """Read registry values from a node and append findings."""
    for name, raw_value in _read_values(registry, hive, key_path, values_selector):
        for value_string in _flatten_registry_value(raw_value):
            registry_path = _build_registry_path(canonical_prefix, key_path, name)
            access_level = (
                AccessLevel.SYSTEM
                if canonical_prefix.startswith("HKLM")
                else AccessLevel.USER
            )
            findings.append(
                make_finding(
                    path=registry_path,
                    value=value_string,
                    access=access_level,
                )
            )


def _collect_findings_from_children(
    registry: RegistryHelper,
    hive: HiveProtocol,
    key_path: str,
    canonical_prefix: str,
    value_name: str,
    findings: list[Finding],
    make_finding: Callable[..., Finding],
) -> None:
    """Iterate child subkeys and read a named value from each."""
    tree = registry.load_subtree(hive, key_path)
    if tree is None:
        return
    access = (
        AccessLevel.SYSTEM if canonical_prefix.startswith("HKLM") else AccessLevel.USER
    )
    for child_name, child_node in tree.children():
        value_str = registry_value_to_str(child_node.get(value_name))
        if value_str is None:
            continue
        registry_path = f"{canonical_prefix}\\{key_path}\\{child_name}\\{value_name}"
        findings.append(
            make_finding(path=registry_path, value=value_str, access=access)
        )


def _read_values(
    registry: RegistryHelper,
    hive: HiveProtocol,
    key_path: str,
    values_selector: str,
) -> Iterator[tuple[str, object]]:
    """Yield (name, value) pairs from the registry node at key_path."""
    node = registry.load_subtree(hive, key_path)
    if node is None:
        return
    if values_selector == "*":
        yield from node.values()
    else:
        registry_value = node.get(values_selector)
        if registry_value is not None:
            yield values_selector, registry_value


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


def _build_registry_path(canonical_prefix: str, key_path: str, value_name: str) -> str:
    """Construct a human-readable registry path."""
    registry_path = f"{canonical_prefix}\\{key_path}" if key_path else canonical_prefix
    if value_name and value_name != "(Default)":
        registry_path = f"{registry_path}\\{value_name}"
    return registry_path
