"""Discovery tests: a broken plugin module may cost only the coverage it owns."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from pyrsistencesniper import plugins as plugins_package
from pyrsistencesniper.core import ledger
from pyrsistencesniper.plugins import (
    PLUGIN_REGISTRY,
    discover_plugins,
)

_PROBE_SOURCES: dict[str, str] = {
    "probe_broken_package/__init__.py": 'raise ImportError("no probe_dependency")',
    "probe_broken_package/probe_child_one.py": "",
    "probe_broken_package/probe_child_two.py": "",
    "probe_crashing_module.py": 'raise RuntimeError("probe module blew up")',
    "probe_crashing_package/__init__.py": 'raise RuntimeError("probe package blew up")',
    "probe_crashing_package/probe_hidden_child.py": "",
    "probe_healthy_module.py": "",
    "probe_healthy_package/__init__.py": "",
    "probe_healthy_package/probe_nested_module.py": "",
}

_EXPECTED_PROBE_FAILURES = {
    "pyrsistencesniper.plugins.probe_broken_package",
    "pyrsistencesniper.plugins.probe_broken_package.probe_child_one",
    "pyrsistencesniper.plugins.probe_broken_package.probe_child_two",
    "pyrsistencesniper.plugins.probe_crashing_module",
    "pyrsistencesniper.plugins.probe_crashing_package",
    "pyrsistencesniper.plugins.probe_crashing_package.probe_hidden_child",
}

_EXPECTED_PROBE_IMPORTS = {
    "pyrsistencesniper.plugins.probe_healthy_module",
    "pyrsistencesniper.plugins.probe_healthy_package",
    "pyrsistencesniper.plugins.probe_healthy_package.probe_nested_module",
}


def _build_probe_tree(root: Path) -> None:
    """Write a plugin subtree whose broken packages hide more modules beneath them."""
    for relative_path, body in _PROBE_SOURCES.items():
        module_path = root / relative_path
        module_path.parent.mkdir(parents=True, exist_ok=True)
        module_path.write_text(f'"""Probe module."""\n\n{body}\n', encoding="utf-8")


def _purge_probe_modules() -> None:
    """Forget every imported probe module so the next discovery starts from scratch."""
    for modname in [
        name
        for name in sys.modules
        if name.startswith("pyrsistencesniper.plugins.probe_")
    ]:
        del sys.modules[modname]


def _imported_probe_modules() -> set[str]:
    """Return the probe modules the discovery walk actually imported."""
    return {
        name
        for name in sys.modules
        if name.startswith("pyrsistencesniper.plugins.probe_")
    }


def _probe_failures() -> set[str]:
    """Return the probe modules the discovery walk recorded as lost coverage."""
    return {
        failure.check_id
        for failure in ledger.failures()
        if failure.check_id.startswith("pyrsistencesniper.plugins.probe_")
    }


@pytest.fixture
def probe_tree(tmp_path: Path) -> Iterator[None]:
    """Graft a subtree of failing and healthy modules onto the real plugin package."""
    _build_probe_tree(tmp_path)
    plugins_package.__path__.append(str(tmp_path))
    importlib.invalidate_caches()
    try:
        yield
    finally:
        plugins_package.__path__.remove(str(tmp_path))
        _purge_probe_modules()
        importlib.invalidate_caches()


@pytest.mark.usefixtures("probe_tree")
def test_broken_package_records_every_module_it_hides() -> None:
    """A package whose __init__ raises must report each check it takes down with it."""
    discover_plugins()
    assert _probe_failures() == _EXPECTED_PROBE_FAILURES


@pytest.mark.usefixtures("probe_tree")
def test_package_raising_non_import_error_does_not_abort_discovery() -> None:
    """A package raising anything other than ImportError must not end the scan."""
    discover_plugins()
    assert "pyrsistencesniper.plugins.probe_crashing_package" in _probe_failures()
    assert "pyrsistencesniper.plugins.probe_healthy_module" in sys.modules


@pytest.mark.usefixtures("probe_tree")
def test_healthy_modules_beside_broken_ones_stay_quiet() -> None:
    """Modules that import cleanly must be loaded and must record no failure."""
    discover_plugins()
    assert _imported_probe_modules() == _EXPECTED_PROBE_IMPORTS
    assert not _probe_failures() & _EXPECTED_PROBE_IMPORTS


def test_real_plugin_tree_imports_without_failure() -> None:
    """The shipped plugin tree must register its checks and record no lost coverage."""
    discover_plugins()
    assert ledger.failures() == ()
    assert len(PLUGIN_REGISTRY) > 100
