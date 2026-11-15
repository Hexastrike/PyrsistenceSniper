"""Declarative check engine: walk registry targets and emit findings."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.core.registry import (
    RegistryHelper,
    registry_key_join,
    registry_value_to_str,
)
from pyrsistencesniper.core.windows import normalize_windows_path

_WOW64_KEY = "Wow6432Node"
_REDIRECTED_HIVE = "SOFTWARE"
_MACHINE_CLASSES_ROOT = "Classes"
_USER_CLASSES_ROOT = "Software\\Classes"


@dataclass(frozen=True, slots=True)
class _HiveContext:
    """One hive to read, the key path to read from it, and the path to report."""

    hive: HiveProtocol
    key_path: str
    canonical_path: str
    deduplicate: bool = False


def execute_definition(
    definition: CheckDefinition,
    context: AnalysisContext,
    make_finding: Callable[..., Finding],
) -> list[Finding]:
    """Walk all declared targets and emit findings."""
    findings: list[Finding] = []
    registry = context.registry
    for target in definition.targets:
        emitted: set[tuple[str, str]] = set()
        for hive_context in _iter_hive_contexts(target, context):
            if target.recurse:
                candidates = _collect_findings_from_children(
                    registry, hive_context, target.values, make_finding
                )
            else:
                candidates = _collect_findings_from_node(
                    registry, hive_context, target.values, make_finding
                )
            findings.extend(_unduplicated(candidates, emitted, hive_context))
    return findings


def _unduplicated(
    candidates: list[Finding],
    emitted: set[tuple[str, str]],
    hive_context: _HiveContext,
) -> list[Finding]:
    """Drop findings another hive sharing this canonical path already produced."""
    if not hive_context.deduplicate:
        return candidates
    kept: list[Finding] = []
    for finding in candidates:
        identity = (finding.path, finding.value)
        if identity in emitted:
            continue
        emitted.add(identity)
        kept.append(finding)
    return kept


def _iter_hive_contexts(
    target: RegistryTarget,
    context: AnalysisContext,
) -> Iterator[_HiveContext]:
    """Yield every hive, read path and canonical path this target covers."""
    yield from _iter_machine_contexts(target, context)
    yield from _iter_user_contexts(target, context)


def _iter_machine_contexts(
    target: RegistryTarget,
    context: AnalysisContext,
) -> Iterator[_HiveContext]:
    """Yield the machine-hive contexts for a target, native view first."""
    if target.scope not in (HiveScope.HKLM, HiveScope.BOTH):
        return

    normalized = normalize_windows_path(target.path).strip("\\") if target.path else ""
    hive_name, _, key_path = normalized.partition("\\")
    if "{controlset}" in key_path:
        key_path = key_path.replace("{controlset}", context.active_controlset)

    hive_path = context.hive_path(hive_name)
    if hive_path is None:
        return
    hive = context.registry.open_hive(hive_path)
    if hive is None:
        return

    canonical_prefix = f"HKLM\\{hive_name}"
    for view_path in _machine_view_paths(hive_name, key_path, target.include_wow64):
        yield _HiveContext(
            hive, view_path, registry_key_join(canonical_prefix, view_path)
        )


def _iter_user_contexts(
    target: RegistryTarget,
    context: AnalysisContext,
) -> Iterator[_HiveContext]:
    """Yield the per-user contexts for a target, NTUSER.DAT then UsrClass.dat."""
    if target.scope not in (HiveScope.HKU, HiveScope.BOTH):
        return

    registry = context.registry
    for user_profile in context.user_profiles:
        canonical_prefix = f"HKU\\{user_profile.username}"
        for view_path in _user_view_paths(target.path, target.include_wow64):
            canonical_path = registry_key_join(canonical_prefix, view_path)
            classes_path = _after_prefix(view_path, _USER_CLASSES_ROOT)
            shared_by_two_hives = classes_path is not None

            if user_profile.ntuser_path is not None:
                ntuser_hive = registry.open_hive(user_profile.ntuser_path)
                if ntuser_hive is not None:
                    yield _HiveContext(
                        ntuser_hive, view_path, canonical_path, shared_by_two_hives
                    )

            if classes_path is None or user_profile.usrclass_path is None:
                continue
            usrclass_hive = registry.open_hive(user_profile.usrclass_path)
            if usrclass_hive is not None:
                yield _HiveContext(usrclass_hive, classes_path, canonical_path, True)


def _machine_view_paths(
    hive_name: str, key_path: str, include_wow64: bool
) -> list[str]:
    """Return the key paths a machine-hive target is read from, native view first."""
    if not include_wow64 or hive_name.upper() != _REDIRECTED_HIVE:
        return [key_path]
    redirected = _insert_after_prefix(key_path, _MACHINE_CLASSES_ROOT, _WOW64_KEY)
    if redirected is None:
        redirected = registry_key_join(_WOW64_KEY, key_path.strip("\\"))
    return [key_path, redirected]


def _user_view_paths(key_path: str, include_wow64: bool) -> list[str]:
    """Return the key paths a per-user target is read from, native view first."""
    if not include_wow64:
        return [key_path]
    redirected = _insert_after_prefix(key_path, _USER_CLASSES_ROOT, _WOW64_KEY)
    return [key_path] if redirected is None else [key_path, redirected]


def _insert_after_prefix(key_path: str, prefix: str, inserted: str) -> str | None:
    """Insert a key name after a leading prefix, keeping the caller's own spelling."""
    remainder = _after_prefix(key_path, prefix)
    if remainder is None:
        return None
    stripped = key_path.strip("\\")
    return registry_key_join(stripped[: len(prefix)], inserted, remainder)


def _after_prefix(key_path: str, prefix: str) -> str | None:
    """Return what follows a leading key prefix, or None when it is not present."""
    stripped = key_path.strip("\\")
    lowered = stripped.lower()
    prefix_lowered = prefix.lower()
    if lowered == prefix_lowered:
        return ""
    if lowered.startswith(prefix_lowered + "\\"):
        return stripped[len(prefix) + 1 :]
    return None


def _collect_findings_from_node(
    registry: RegistryHelper,
    hive_context: _HiveContext,
    values_selector: str,
    make_finding: Callable[..., Finding],
) -> list[Finding]:
    """Read registry values from a node and return the findings they yield."""
    findings: list[Finding] = []
    access_level = _access_level(hive_context.canonical_path)
    for name, raw_value in _read_values(
        registry, hive_context.hive, hive_context.key_path, values_selector
    ):
        registry_path = _build_registry_path(hive_context.canonical_path, name)
        findings.extend(
            make_finding(path=registry_path, value=value_string, access=access_level)
            for value_string in _flatten_registry_value(raw_value)
        )
    return findings


def _collect_findings_from_children(
    registry: RegistryHelper,
    hive_context: _HiveContext,
    value_name: str,
    make_finding: Callable[..., Finding],
) -> list[Finding]:
    """Iterate child subkeys and read a named value from each."""
    tree = registry.load_subtree(hive_context.hive, hive_context.key_path)
    if tree is None:
        return []
    findings: list[Finding] = []
    access_level = _access_level(hive_context.canonical_path)
    for child_name, child_node in tree.children():
        value_string = registry_value_to_str(child_node.get(value_name))
        if value_string is None:
            continue
        registry_path = f"{hive_context.canonical_path}\\{child_name}\\{value_name}"
        findings.append(
            make_finding(path=registry_path, value=value_string, access=access_level)
        )
    return findings


def _access_level(canonical_path: str) -> AccessLevel:
    """Return the privilege level a write to this canonical path implies."""
    return AccessLevel.SYSTEM if canonical_path.startswith("HKLM") else AccessLevel.USER


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
    """Convert a raw registry value to a list of non-blank strings."""
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


def _build_registry_path(canonical_path: str, value_name: str) -> str:
    """Construct a human-readable registry path."""
    if value_name and value_name != "(Default)":
        return f"{canonical_path}\\{value_name}"
    return canonical_path
