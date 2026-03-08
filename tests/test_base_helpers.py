from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.forensics.registry import RegistryNode
from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin


class _StubPlugin(PersistencePlugin):
    definition = CheckDefinition(
        id="stub_check",
        technique="Stub Technique",
        mitre_id="T9999",
        description="Stub description for testing",
        references=("https://example.com/ref1", "https://example.com/ref2"),
    )


def _make_plugin() -> _StubPlugin:
    context = MagicMock(spec=AnalysisContext)
    type(context).hostname = PropertyMock(return_value="TESTHOST")
    context.registry = MagicMock()
    context.filesystem = MagicMock()
    context.profile = MagicMock()
    return _StubPlugin(context=context)


# -- _open_hive ----------------------------------------------------------------


def test_open_hive_returns_hive() -> None:
    plugin = _make_plugin()
    sentinel = object()
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = sentinel

    result = plugin._open_hive("SYSTEM")
    assert result is sentinel
    plugin.context.hive_path.assert_called_once_with("SYSTEM")
    plugin.registry.open_hive.assert_called_once_with(Path("/fake/SYSTEM"))


def test_open_hive_returns_none_when_no_path() -> None:
    plugin = _make_plugin()
    plugin.context.hive_path.return_value = None

    result = plugin._open_hive("SOFTWARE")
    assert result is None
    plugin.registry.open_hive.assert_not_called()


def test_open_hive_returns_none_when_open_fails() -> None:
    plugin = _make_plugin()
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = None

    result = plugin._open_hive("SYSTEM")
    assert result is None


# -- _make_finding -------------------------------------------------------------


def test_make_finding_populates_all_fields() -> None:
    plugin = _make_plugin()
    finding = plugin._make_finding(
        path="HKLM\\SOFTWARE\\Run\\evil",
        value="evil.exe",
        access=AccessLevel.SYSTEM,
    )
    assert finding.path == "HKLM\\SOFTWARE\\Run\\evil"
    assert finding.value == "evil.exe"
    assert finding.technique == "Stub Technique"
    assert finding.mitre_id == "T9999"
    assert finding.description == "Stub description for testing"
    assert finding.access_gained == AccessLevel.SYSTEM
    assert finding.hostname == "TESTHOST"
    assert finding.check_id == "stub_check"
    assert finding.references == (
        "https://example.com/ref1",
        "https://example.com/ref2",
    )


def test_make_finding_user_access() -> None:
    plugin = _make_plugin()
    finding = plugin._make_finding(
        path="HKU\\user\\Run\\app",
        value="app.exe",
        access=AccessLevel.USER,
    )
    assert finding.access_gained == AccessLevel.USER


def test_make_finding_custom_description() -> None:
    plugin = _make_plugin()
    finding = plugin._make_finding(
        path="HKLM\\Run\\test",
        value="test.exe",
        access=AccessLevel.SYSTEM,
        description="Custom description",
    )
    assert finding.description == "Custom description"


# -- _resolve_clsid_default ---------------------------------------------------


def _make_node(values: dict[str, object]) -> RegistryNode:
    """Build a RegistryNode from {name: data} pairs."""
    val_dict = {k.lower(): (k, v) for k, v in values.items()}
    return RegistryNode("test", val_dict, {})


def test_resolve_clsid_default_found() -> None:
    plugin = _make_plugin()
    hive = MagicMock()
    plugin.registry.load_subtree.return_value = _make_node(
        {"": "C:\\Windows\\evil.dll", "ThreadingModel": "Both"}
    )

    subpath = "Classes\\CLSID\\{abc}\\InprocServer32"
    result = plugin._resolve_clsid_default(hive, subpath)
    assert result == "C:\\Windows\\evil.dll"


def test_resolve_clsid_default_not_found() -> None:
    plugin = _make_plugin()
    hive = MagicMock()
    plugin.registry.load_subtree.return_value = _make_node({"ThreadingModel": "Both"})

    subpath = "Classes\\CLSID\\{abc}\\InprocServer32"
    result = plugin._resolve_clsid_default(hive, subpath)
    assert result == ""


def test_resolve_clsid_default_empty_value() -> None:
    plugin = _make_plugin()
    hive = MagicMock()
    plugin.registry.load_subtree.return_value = _make_node({"(Default)": ""})

    subpath = "Classes\\CLSID\\{abc}\\InprocServer32"
    result = plugin._resolve_clsid_default(hive, subpath)
    assert result == ""
