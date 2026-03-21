"""Tests for the ContentIndexDll plugin (T1574).

Detects DLLOverridePath under ContentIndex\\Language subkeys.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1574.content_index_dll import ContentIndexDll

from .conftest import make_deps, make_node


def _make_plugin(tmp_path: Path) -> ContentIndexDll:
    context, _registry, _fs, _profile = make_deps(tmp_path)
    return ContentIndexDll(context=context)


def test_dll_override_detected(tmp_path: Path) -> None:
    """DLLOverridePath in a language subkey produces a finding."""
    lang_node = make_node(values={"DLLOverridePath": r"C:\evil.dll"})
    tree = make_node(children={"English_US": lang_node})

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = tree

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == r"C:\evil.dll"
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert "DLLOverridePath" in findings[0].path


def test_no_override_no_finding(tmp_path: Path) -> None:
    """Language subkey without DLLOverridePath produces no findings."""
    lang_node = make_node(values={"SomeOtherValue": "stuff"})
    tree = make_node(children={"English_US": lang_node})

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = tree

    findings = plugin.run()
    assert findings == []


def test_missing_hive(tmp_path: Path) -> None:
    """Missing SYSTEM hive produces no findings."""
    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = None

    findings = plugin.run()
    assert findings == []


def test_missing_language_key(tmp_path: Path) -> None:
    """SYSTEM hive exists but ContentIndex\\Language key is absent."""
    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = None

    findings = plugin.run()
    assert findings == []


def test_multiple_languages_with_override(tmp_path: Path) -> None:
    """Multiple language subkeys each with DLLOverridePath produce multiple findings."""
    lang_en = make_node(values={"DLLOverridePath": r"C:\en.dll"})
    lang_de = make_node(values={"DLLOverridePath": r"C:\de.dll"})
    tree = make_node(children={"English_US": lang_en, "German": lang_de})

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = tree

    findings = plugin.run()
    assert len(findings) == 2
    values = {f.value for f in findings}
    assert values == {r"C:\en.dll", r"C:\de.dll"}
