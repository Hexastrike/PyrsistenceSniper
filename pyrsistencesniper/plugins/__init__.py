from __future__ import annotations

import logging
import pkgutil

from pyrsistencesniper.core.pipeline import run_all_checks
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)


_PLUGIN_REGISTRY: dict[str, type[PersistencePlugin]] = {}


def register_plugin(cls: type[PersistencePlugin]) -> type[PersistencePlugin]:
    """Class decorator that adds a plugin to the global plugin registry."""
    check_id = cls.definition.id
    _PLUGIN_REGISTRY[check_id] = cls
    return cls


def _discover_plugins() -> None:
    """Walk and import all plugin submodules to trigger registration decorators."""
    for _importer, modname, _ispkg in pkgutil.walk_packages(
        __path__, prefix=__name__ + "."
    ):
        try:
            __import__(modname)
        except Exception:
            logger.warning("Failed to import plugin module %s", modname)
            logger.debug("Plugin import error details:", exc_info=True)


__all__ = [
    "_PLUGIN_REGISTRY",
    "_discover_plugins",
    "register_plugin",
    "run_all_checks",
]
