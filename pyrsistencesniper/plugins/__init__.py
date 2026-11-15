"""Plugin registry and auto-discovery for persistence detection plugins."""

from __future__ import annotations

import logging
import pkgutil
import sys
from pathlib import Path

from pyrsistencesniper.core import ledger
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)


_PLUGIN_REGISTRY: dict[str, type[PersistencePlugin]] = {}


def register_plugin(cls: type[PersistencePlugin]) -> type[PersistencePlugin]:
    """Class decorator that adds a plugin to the global plugin registry."""
    check_id = cls.definition.id
    existing = _PLUGIN_REGISTRY.get(check_id)
    # Overwriting a duplicate id would silently drop the replaced check from scans.
    if existing is not None and existing is not cls:
        msg = (
            f"duplicate check id {check_id!r}: "
            f"{existing.__module__}.{existing.__qualname__} and "
            f"{cls.__module__}.{cls.__qualname__}"
        )
        raise ValueError(msg)
    _PLUGIN_REGISTRY[check_id] = cls
    return cls


def _try_import(modname: str) -> None:
    """Attempt to import a single plugin module, recording failures as lost coverage."""
    try:
        __import__(modname)
    except Exception as exc:
        logger.warning("Failed to import plugin module %s", modname)
        logger.debug("Plugin import error details:", exc_info=True)
        ledger.record_check_failure(modname, exc)


def _package_search_paths(modname: str, module_finder: object) -> list[str]:
    """Return the directories a package holds its submodules in, imported or not."""
    imported_package = sys.modules.get(modname)
    declared_paths = getattr(imported_package, "__path__", None)
    if declared_paths is not None:
        return [str(declared_path) for declared_path in declared_paths]
    parent_directory = getattr(module_finder, "path", None)
    if not isinstance(parent_directory, str):
        logger.debug("No search path for package %s; its modules are lost", modname)
        return []
    package_directory = Path(parent_directory) / modname.rpartition(".")[2]
    return [str(package_directory)] if package_directory.is_dir() else []


def _import_module_tree(
    search_paths: list[str], prefix: str, visited_paths: set[str]
) -> None:
    """Import every module below these paths, descending into packages that raised."""
    for module_finder, modname, is_package in pkgutil.iter_modules(
        search_paths, prefix
    ):
        _try_import(modname)
        if not is_package:
            continue
        child_paths = [
            child_path
            for child_path in _package_search_paths(modname, module_finder)
            if child_path not in visited_paths
        ]
        visited_paths.update(child_paths)
        _import_module_tree(child_paths, modname + ".", visited_paths)


def _discover_plugins() -> None:
    """Walk and import all plugin submodules to trigger registration decorators."""
    search_paths = [str(search_path) for search_path in __path__]
    _import_module_tree(search_paths, __name__ + ".", set(search_paths))


__all__ = [
    "_PLUGIN_REGISTRY",
    "_discover_plugins",
    "register_plugin",
]
