"""Permanent enforcement tests for module dependency boundaries.

These tests parse every .py file using the ast module and verify that:
1. No module imports from a higher architectural layer (downward-only deps).
2. Plugin T* files import only from plugins.base and plugins (register_plugin).
3. No plugin T* module imports from another plugin T* module.

Any violation causes a hard test failure with a descriptive message naming
the offending file and import.
"""

from __future__ import annotations

import ast
from pathlib import Path

_PACKAGE_ROOT = Path("pyrsistencesniper")

# Architectural layers -- lower number means lower in the dependency stack.
# A module at layer N may only import from layers <= N.
LAYERS: dict[str, int] = {
    "config": 0,
    "data": 0,
    "core": 1,
    "plugins": 2,
    "enrichment": 2,
    "output": 3,
    "ui": 3,
}

# Named exceptions: (source_file_relative, target_module_prefix)
# core/pipeline.py is the top-level orchestrator that necessarily imports from
# plugins (layer 2) and enrichment (layer 2) to run the detection pipeline.
_ALLOWED_UPWARD_IMPORTS: set[tuple[str, str]] = {
    ("core/pipeline.py", "pyrsistencesniper.enrichment"),
    ("core/pipeline.py", "pyrsistencesniper.plugins"),
    ("core/pipeline.py", "pyrsistencesniper.plugins.base"),
}


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


def test_no_upward_imports() -> None:
    """No module imports from a higher architectural layer."""
    violations: list[str] = []

    for py_file in sorted(_PACKAGE_ROOT.rglob("*.py")):
        rel = _relative_path(py_file)
        parts = rel.split("/")

        # Skip top-level package files (cli.py, __init__.py, __main__.py)
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
                # Check named exceptions
                pair = (rel, target_module)
                if pair in _ALLOWED_UPWARD_IMPORTS:
                    continue
                violations.append(
                    f"  {rel} (layer {source_layer}) imports "
                    f"{target_module} (layer {target_level})"
                )

    assert not violations, "Upward imports violate dependency direction:\n" + "\n".join(
        violations
    )


def test_plugins_only_import_from_base() -> None:
    """All plugin T* files import only from plugins.base or plugins."""
    violations: list[str] = []

    for py_file in sorted(_PACKAGE_ROOT.rglob("*.py")):
        rel = _relative_path(py_file)
        parts = rel.split("/")

        # Only check plugins/T*/**/*.py files
        if len(parts) < 3 or parts[0] != "plugins" or not parts[1].startswith("T"):
            continue

        for target_module in _extract_imports(py_file):
            # Allowed: pyrsistencesniper.plugins.base, pyrsistencesniper.plugins,
            # and pyrsistencesniper.core.* (plugins legitimately use core utilities)
            if target_module in (
                "pyrsistencesniper.plugins.base",
                "pyrsistencesniper.plugins",
            ):
                continue
            if target_module.startswith("pyrsistencesniper.core"):
                continue
            # Any other pyrsistencesniper.* import is forbidden
            violations.append(f"  {rel} imports {target_module}")

    assert not violations, (
        "Plugin files must import only from plugins.base or plugins:\n"
        + "\n".join(violations)
    )


def test_no_cross_plugin_imports() -> None:
    """No plugin T* module imports from another plugin T* module."""
    violations: list[str] = []

    for py_file in sorted(_PACKAGE_ROOT.rglob("*.py")):
        rel = _relative_path(py_file)
        parts = rel.split("/")

        # Only check plugins/T*/**/*.py files
        if len(parts) < 3 or parts[0] != "plugins" or not parts[1].startswith("T"):
            continue

        source_t_dir = parts[1]  # e.g. "T1546"

        for target_module in _extract_imports(py_file):
            # Check for imports like pyrsistencesniper.plugins.T*
            mod_parts = target_module.split(".")
            if (
                len(mod_parts) >= 3
                and mod_parts[1] == "plugins"
                and mod_parts[2].startswith("T")
            ):
                target_t_dir = mod_parts[2]
                if target_t_dir != source_t_dir:
                    violations.append(
                        f"  {rel} imports from {target_module} "
                        f"(cross-plugin: {source_t_dir} -> {target_t_dir})"
                    )

    assert not violations, "Cross-plugin imports are forbidden:\n" + "\n".join(
        violations
    )
