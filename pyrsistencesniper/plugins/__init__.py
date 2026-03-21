"""Plugin registry and auto-discovery for persistence detection plugins."""

from __future__ import annotations

from pyrsistencesniper.plugins.runner import (
    _PLUGIN_REGISTRY,
    register_plugin,
)
from pyrsistencesniper.plugins.runner import (
    _discover_plugins as _discover_plugins_impl,
)

__all__ = [
    "_PLUGIN_REGISTRY",
    "_discover_plugins",
    "register_plugin",
]


def _discover_plugins() -> None:
    """Walk and import all plugin submodules to trigger registration decorators."""
    _discover_plugins_impl(__path__, __name__)
