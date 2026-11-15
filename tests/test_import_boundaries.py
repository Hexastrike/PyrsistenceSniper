"""Enforcement tests for the package's layered import boundaries."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

_PACKAGE_ROOT = Path("pyrsistencesniper")

# Lower layer number = lower in the stack; a module may import layers <= its own.
LAYERS: dict[str, int] = {
    "config": 0,
    "data": 0,
    "core": 1,
    "detection": 2,
    "plugins": 2,
    "timeline": 2,
    "output": 3,
    "ui": 3,
}

# Entries are (source_file_relative, target_module).
_ALLOWED_UPWARD_IMPORTS: set[tuple[str, str]] = set()


def _extract_imports(filepath: Path) -> list[str]:
    """Parse a .py file and return all pyrsistencesniper.* import targets."""
    source = filepath.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return []

    targets: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith("pyrsistencesniper"):
                targets.append(node.module)
        elif isinstance(node, ast.Import):
            targets.extend(
                alias.name
                for alias in node.names
                if alias.name.startswith("pyrsistencesniper")
            )
    return targets


def _get_layer(module_path: str) -> tuple[str, int] | None:
    """Return (subpackage_name, layer_level) for a pyrsistencesniper module."""
    parts = module_path.split(".")
    if len(parts) < 2:
        return None
    subpackage = parts[1]
    level = LAYERS.get(subpackage)
    if level is None:
        return None
    return subpackage, level


def _relative_path(filepath: Path) -> str:
    """Return the path relative to the package root, using forward slashes."""
    return filepath.relative_to(_PACKAGE_ROOT).as_posix()


def _iter_package_modules() -> Iterator[tuple[Path, str]]:
    """Yield every package source file with its package-relative path."""
    for py_file in sorted(_PACKAGE_ROOT.rglob("*.py")):
        yield py_file, _relative_path(py_file)


def _iter_technique_modules() -> Iterator[tuple[Path, str, str]]:
    """Yield each plugins/T*/ module with its relative path and technique directory."""
    for py_file, module_path in _iter_package_modules():
        parts = module_path.split("/")
        if len(parts) >= 3 and parts[0] == "plugins" and parts[1].startswith("T"):
            yield py_file, module_path, parts[1]


def test_no_upward_imports() -> None:
    """No module imports from a higher architectural layer."""
    violations: list[str] = []

    for py_file, module_path in _iter_package_modules():
        parts = module_path.split("/")
        if len(parts) < 2:
            continue

        source_layer = LAYERS.get(parts[0])
        if source_layer is None:
            continue

        for target_module in _extract_imports(py_file):
            target_info = _get_layer(target_module)
            if target_info is None:
                continue
            _, target_level = target_info

            if target_level > source_layer:
                if (module_path, target_module) in _ALLOWED_UPWARD_IMPORTS:
                    continue
                violations.append(
                    f"  {module_path} (layer {source_layer}) imports "
                    f"{target_module} (layer {target_level})"
                )

    assert not violations, "Upward imports violate dependency direction:\n" + "\n".join(
        violations
    )


def test_plugins_only_import_from_base() -> None:
    """Plugins stay swappable only while they depend on base and core alone."""
    allowed = ("pyrsistencesniper.plugins.base", "pyrsistencesniper.plugins")
    violations = [
        f"  {module_path} imports {target_module}"
        for py_file, module_path, _technique_dir in _iter_technique_modules()
        for target_module in _extract_imports(py_file)
        if target_module not in allowed
        and not target_module.startswith("pyrsistencesniper.core")
    ]

    assert not violations, (
        "Plugin files must import only from plugins.base or plugins:\n"
        + "\n".join(violations)
    )


def test_no_cross_plugin_imports() -> None:
    """No plugin T* module imports from another plugin T* module."""
    violations: list[str] = []

    for py_file, module_path, source_technique in _iter_technique_modules():
        for target_module in _extract_imports(py_file):
            target_parts = target_module.split(".")
            if (
                len(target_parts) >= 3
                and target_parts[1] == "plugins"
                and target_parts[2].startswith("T")
                and target_parts[2] != source_technique
            ):
                violations.append(
                    f"  {module_path} imports from {target_module} "
                    f"(cross-plugin: {source_technique} -> {target_parts[2]})"
                )

    assert not violations, "Cross-plugin imports are forbidden:\n" + "\n".join(
        violations
    )


def test_core_registry_is_pure() -> None:
    """core/registry.py is a pure library: no context/detection/plugin imports."""
    forbidden_prefixes = (
        "pyrsistencesniper.core.context",
        "pyrsistencesniper.core.filesystem",
        "pyrsistencesniper.detection",
        "pyrsistencesniper.plugins",
        "pyrsistencesniper.output",
        "pyrsistencesniper.ui",
    )
    registry_module = _PACKAGE_ROOT / "core" / "registry.py"
    violations = [
        f"  {_relative_path(registry_module)} imports {target}"
        for target in _extract_imports(registry_module)
        if target.startswith(forbidden_prefixes)
    ]
    assert not violations, "core/registry.py must stay a pure library:\n" + "\n".join(
        violations
    )


def test_no_references_to_removed_modules() -> None:
    """No module may reference a package path retired by the flattening."""
    retired = (
        "pyrsistencesniper.core.image",
        "pyrsistencesniper.core.registry.helper",
        "pyrsistencesniper.core.registry.node",
        "pyrsistencesniper.core.windows.paths",
        "pyrsistencesniper.core.windows.cmdline",
        "pyrsistencesniper.core.windows.classify",
    )
    violations: list[str] = []
    for py_file, module_path in _iter_package_modules():
        violations.extend(
            f"  {module_path} imports {target}"
            for target in _extract_imports(py_file)
            if target.startswith(retired)
        )
    assert not violations, "References to retired modules:\n" + "\n".join(violations)


def test_detection_engine_has_no_plugin_imports() -> None:
    """detection/ must not import plugins/, except the pipeline orchestrator."""
    violations: list[str] = []
    detection_dir = _PACKAGE_ROOT / "detection"
    for py_file in sorted(detection_dir.rglob("*.py")):
        module_path = _relative_path(py_file)
        if module_path == "detection/pipeline.py":
            continue
        violations.extend(
            f"  {module_path} imports {target}"
            for target in _extract_imports(py_file)
            if target.startswith("pyrsistencesniper.plugins")
        )
    assert not violations, (
        "detection/ must not import plugins/ "
        "(prevents detection.engine ↔ plugins.base cycle):\n" + "\n".join(violations)
    )
