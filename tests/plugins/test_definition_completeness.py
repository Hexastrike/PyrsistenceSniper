"""Programmatic test that all registered plugins have complete CheckDefinition metadata.

Guards against missing descriptions, references, or malformed MITRE ATT&CK IDs
across every plugin in the registry (PLUG-05).
"""

from __future__ import annotations

import re

from pyrsistencesniper.plugins import _PLUGIN_REGISTRY, _discover_plugins

_MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_all_plugins_have_complete_definitions() -> None:
    """Every registered plugin has complete CheckDefinition metadata."""
    _discover_plugins()
    assert len(_PLUGIN_REGISTRY) >= 94, (
        f"Expected >= 94 registered plugins, found {len(_PLUGIN_REGISTRY)}"
    )
    for check_id, plugin_cls in _PLUGIN_REGISTRY.items():
        defn = plugin_cls.definition
        assert defn.id, f"{check_id}: missing id"
        assert defn.technique, f"{check_id}: missing technique"
        assert _MITRE_ID_RE.match(defn.mitre_id), (
            f"{check_id}: mitre_id '{defn.mitre_id}' must match T\\d{{4}}(\\.\\d{{3}})?"
        )
        desc = defn.description
        assert desc, f"{check_id}: missing description"
        assert len(desc) > 10, (
            f"{check_id}: description must be >10 chars, got: {desc!r}"
        )
        assert defn.references, f"{check_id}: missing references"
