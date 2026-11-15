"""Tests for the plugin base class and the declarative detection engine."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, PropertyMock, create_autospec

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    HiveScope,
    RegistryTarget,
    UserProfile,
)
from pyrsistencesniper.core.registry import RegistryNode
from pyrsistencesniper.plugins.base import PersistencePlugin


class _StubPlugin(PersistencePlugin):
    """Definition-only plugin: no targets, so only _make_finding is exercised."""

    definition = CheckDefinition(
        id="stub_check",
        technique="Stub Technique",
        mitre_id="T9999",
        description="Stub description for testing",
        references=("https://example.com/ref1", "https://example.com/ref2"),
    )


def _make_stub_plugin() -> _StubPlugin:
    """Build a _StubPlugin whose context reports hostname TESTHOST."""
    context = create_autospec(AnalysisContext, instance=True)
    type(context).hostname = PropertyMock(return_value="TESTHOST")
    context.registry = MagicMock()
    context.filesystem = MagicMock()
    return _StubPlugin(context=context)


def test_make_finding_populates_all_fields() -> None:
    """A Finding inherits all its metadata from the definition and the context."""
    plugin = _make_stub_plugin()
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
        "https://attack.mitre.org/techniques/T9999/",
        "https://example.com/ref1",
        "https://example.com/ref2",
    )


def test_make_finding_custom_description() -> None:
    """A per-finding description overrides the definition's generic one."""
    plugin = _make_stub_plugin()
    finding = plugin._make_finding(
        path="HKLM\\Run\\test",
        value="test.exe",
        access=AccessLevel.SYSTEM,
        description="Custom description",
    )
    assert finding.description == "Custom description"


def _node(
    values: dict[str, object], children: dict[str, RegistryNode] | None = None
) -> RegistryNode:
    """Build a RegistryNode, keying value names lowercase as the real reader does."""
    val_dict = {name.lower(): (name, value) for name, value in values.items()}
    child_dict = children or {}
    return RegistryNode("test", val_dict, child_dict)


def _make_plugin(
    targets: tuple[RegistryTarget, ...],
    *,
    user_profiles: list[UserProfile] | None = None,
    controlset: str = "ControlSet001",
) -> PersistencePlugin:
    """Build a plugin for these targets; the caller stubs registry return values."""

    class _Stub(PersistencePlugin):
        """Plugin carrying only the targets under test."""

        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub",
            technique="Stub",
            mitre_id="T0000",
            targets=targets,
        )

    context = create_autospec(AnalysisContext, instance=True)
    type(context).hostname = PropertyMock(return_value="TESTHOST")
    type(context).active_controlset = PropertyMock(return_value=controlset)
    type(context).user_profiles = PropertyMock(return_value=user_profiles or [])
    context.registry = MagicMock()
    context.filesystem = MagicMock()

    return _Stub(context=context)


def _wire_hive(
    plugin: PersistencePlugin,
    tree: RegistryNode | None,
    *,
    hive_path: str = "/fake/SOFTWARE",
) -> MagicMock:
    """Wire one machine hive answering every key path with tree, and return it."""
    plugin.context.hive_path.return_value = Path(hive_path)
    hive = MagicMock()
    plugin.registry.open_hive.return_value = hive
    plugin.registry.load_subtree.return_value = tree
    return hive


def test_hklm_wildcard_values() -> None:
    """A wildcard target reports every value in the key, each as SYSTEM access."""
    target = RegistryTarget(
        path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", scope=HiveScope.HKLM
    )
    plugin = _make_plugin((target,))

    _wire_hive(plugin, _node({"EvilApp": "evil.exe", "GoodApp": "good.exe"}))

    findings = plugin.run()
    assert len(findings) == 2
    values = {finding.value for finding in findings}
    assert values == {"evil.exe", "good.exe"}
    assert all(finding.path.startswith("HKLM\\SOFTWARE") for finding in findings)
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)


def test_hklm_specific_value() -> None:
    """Naming a value confines the check to it; sibling entries stay unreported."""
    target = RegistryTarget(
        path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        values="AutoRun",
        scope=HiveScope.HKLM,
    )
    plugin = _make_plugin((target,))

    _wire_hive(plugin, _node({"AutoRun": "malware.exe", "Other": "benign.exe"}))

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "malware.exe"


def test_hklm_missing_hive_returns_empty() -> None:
    """An image lacking the hive file scans clean instead of raising."""
    target = RegistryTarget(path=r"SOFTWARE\Run", scope=HiveScope.HKLM)
    plugin = _make_plugin((target,))
    plugin.context.hive_path.return_value = None

    findings = plugin.run()
    assert findings == []


def test_hklm_missing_key_returns_empty() -> None:
    """A hive without the key is a clean absence, not a scan failure."""
    target = RegistryTarget(path=r"SOFTWARE\Run", scope=HiveScope.HKLM)
    plugin = _make_plugin((target,))
    _wire_hive(plugin, None)

    findings = plugin.run()
    assert findings == []


def test_hku_iterates_user_profiles() -> None:
    """Each profile's hive is scanned and attributed to its own user at USER access."""
    target = RegistryTarget(
        path=r"Microsoft\Windows\CurrentVersion\Run",
        scope=HiveScope.HKU,
    )
    profiles = [
        UserProfile(
            username="alice",
            profile_path=Path("/Users/alice"),
            ntuser_path=Path("/Users/alice/NTUSER.DAT"),
        ),
        UserProfile(
            username="bob",
            profile_path=Path("/Users/bob"),
            ntuser_path=Path("/Users/bob/NTUSER.DAT"),
        ),
    ]
    plugin = _make_plugin((target,), user_profiles=profiles)

    hive_a = MagicMock()
    hive_b = MagicMock()
    plugin.registry.open_hive.side_effect = [hive_a, hive_b]
    plugin.registry.load_subtree.side_effect = [
        _node({"Payload": "a.exe"}),
        _node({"Payload": "b.exe"}),
    ]

    findings = plugin.run()
    assert len(findings) == 2
    assert findings[0].path.startswith("HKU\\alice")
    assert findings[1].path.startswith("HKU\\bob")
    assert all(finding.access_gained == AccessLevel.USER for finding in findings)


def test_hku_skips_profile_without_ntuser() -> None:
    """A profile with no NTUSER.DAT is skipped, not treated as an error."""
    target = RegistryTarget(path=r"Run", scope=HiveScope.HKU)
    profiles = [
        UserProfile(
            username="nohive", profile_path=Path("/Users/nohive"), ntuser_path=None
        ),
    ]
    plugin = _make_plugin((target,), user_profiles=profiles)
    findings = plugin.run()
    assert findings == []


def test_both_scope_emits_hklm_and_hku() -> None:
    """BOTH visits machine and user hives in one pass, keeping the scopes distinct."""
    target = RegistryTarget(
        path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        scope=HiveScope.BOTH,
    )
    profiles = [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]
    plugin = _make_plugin((target,), user_profiles=profiles)

    hklm_hive = MagicMock()
    hku_hive = MagicMock()
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
    plugin.registry.open_hive.side_effect = [hklm_hive, hku_hive]
    plugin.registry.load_subtree.side_effect = [
        _node({"SysApp": "sys.exe"}),
        _node({"UserApp": "user.exe"}),
    ]

    findings = plugin.run()
    assert len(findings) == 2
    hklm_findings = [finding for finding in findings if finding.path.startswith("HKLM")]
    hku_findings = [finding for finding in findings if finding.path.startswith("HKU")]
    assert len(hklm_findings) == 1
    assert len(hku_findings) == 1


def test_controlset_placeholder_replaced() -> None:
    """{controlset} resolves to the image's active set, not a fixed ControlSet001."""
    target = RegistryTarget(
        path=r"SYSTEM\{controlset}\Services",
        scope=HiveScope.HKLM,
    )
    plugin = _make_plugin((target,), controlset="ControlSet002")

    hive = _wire_hive(plugin, _node({"Svc": "svc.dll"}), hive_path="/fake/SYSTEM")

    plugin.run()
    plugin.registry.load_subtree.assert_called_once_with(
        hive, r"ControlSet002\Services"
    )


def test_multi_value_string_expanded() -> None:
    """Each entry of a multi-string becomes a finding, so none hides in the list."""
    target = RegistryTarget(path=r"SOFTWARE\Key", values="Multi", scope=HiveScope.HKLM)
    plugin = _make_plugin((target,))

    _wire_hive(plugin, _node({"Multi": ["one.dll", "two.dll", "three.dll"]}))

    findings = plugin.run()
    assert len(findings) == 3
    assert {finding.value for finding in findings} == {
        "one.dll",
        "two.dll",
        "three.dll",
    }


def test_scalar_blank_value_skipped() -> None:
    """An empty value is not persistence, so it never reaches the report."""
    target = RegistryTarget(path=r"SOFTWARE\Key", values="Val", scope=HiveScope.HKLM)
    plugin = _make_plugin((target,))

    _wire_hive(plugin, _node({"Val": ""}))

    findings = plugin.run()
    assert findings == []


def test_scalar_whitespace_value_skipped() -> None:
    """Whitespace counts as empty; padding a value does not smuggle it into results."""
    target = RegistryTarget(path=r"SOFTWARE\Key", values="Val", scope=HiveScope.HKLM)
    plugin = _make_plugin((target,))

    _wire_hive(plugin, _node({"Val": "   "}))

    findings = plugin.run()
    assert findings == []


def test_multi_value_string_filters_blanks() -> None:
    """Blank entries drop out of a multi-string while the real one survives."""
    target = RegistryTarget(path=r"SOFTWARE\Key", values="Multi", scope=HiveScope.HKLM)
    plugin = _make_plugin((target,))

    _wire_hive(plugin, _node({"Multi": ["real.dll", "", "  "]}))

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "real.dll"


def test_recurse_reads_child_values() -> None:
    """Recursion reads the named value from every subkey, one finding per child."""
    target = RegistryTarget(
        path=r"SYSTEM\Services\Providers",
        values="Driver",
        scope=HiveScope.HKLM,
        recurse=True,
    )
    child_a = _node({"Driver": "a.dll"}, children={})
    child_b = _node({"Driver": "b.dll"}, children={})
    tree = _node({}, children={"ChildA": child_a, "ChildB": child_b})
    plugin = _make_plugin((target,))

    _wire_hive(plugin, tree, hive_path="/fake/SYSTEM")

    findings = plugin.run()
    assert len(findings) == 2
    assert {finding.value for finding in findings} == {"a.dll", "b.dll"}
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)


def test_recurse_skips_children_without_target_value() -> None:
    """A subkey lacking the named value is passed over, not reported as blank."""
    target = RegistryTarget(
        path=r"SYSTEM\Services\Providers",
        values="Driver",
        scope=HiveScope.HKLM,
        recurse=True,
    )
    child = _node({"OtherValue": "irrelevant"}, children={})
    tree = _node({}, children={"Child": child})
    plugin = _make_plugin((target,))

    _wire_hive(plugin, tree, hive_path="/fake/SYSTEM")

    assert plugin.run() == []


def test_recurse_empty_subtree() -> None:
    """A key with no subkeys yields nothing rather than erroring on the walk."""
    target = RegistryTarget(
        path=r"SYSTEM\Services\Providers",
        values="Driver",
        scope=HiveScope.HKLM,
        recurse=True,
    )
    tree = _node({}, children={})
    plugin = _make_plugin((target,))

    _wire_hive(plugin, tree, hive_path="/fake/SYSTEM")

    assert plugin.run() == []


def test_recurse_missing_key_returns_empty() -> None:
    """A missing parent key ends the walk quietly instead of raising."""
    target = RegistryTarget(
        path=r"SYSTEM\Services\Providers",
        values="Driver",
        scope=HiveScope.HKLM,
        recurse=True,
    )
    plugin = _make_plugin((target,))

    _wire_hive(plugin, None, hive_path="/fake/SYSTEM")

    assert plugin.run() == []


def test_recurse_path_includes_child_name() -> None:
    """The child key name lands in the path, so a hit points at the exact subkey."""
    target = RegistryTarget(
        path=r"SYSTEM\Services\Providers",
        values="DllName",
        scope=HiveScope.HKLM,
        recurse=True,
    )
    child = _node({"DllName": "test.dll"}, children={})
    tree = _node({}, children={"MyProvider": child})
    plugin = _make_plugin((target,))

    _wire_hive(plugin, tree, hive_path="/fake/SYSTEM")

    findings = plugin.run()
    assert len(findings) == 1
    assert r"Services\Providers\test\DllName" in findings[0].path
    assert findings[0].path.startswith("HKLM\\SYSTEM")


def test_recurse_with_controlset() -> None:
    """{controlset} is substituted on recursive walks too, not just flat keys."""
    target = RegistryTarget(
        path=r"SYSTEM\{controlset}\Services\Providers",
        values="DllName",
        scope=HiveScope.HKLM,
        recurse=True,
    )
    child = _node({"DllName": "tp.dll"}, children={})
    tree = _node({}, children={"Provider1": child})
    plugin = _make_plugin((target,), controlset="ControlSet002")

    hive = _wire_hive(plugin, tree, hive_path="/fake/SYSTEM")

    findings = plugin.run()
    assert len(findings) == 1
    assert "ControlSet002" in findings[0].path
    plugin.registry.load_subtree.assert_called_once_with(
        hive, r"ControlSet002\Services\Providers"
    )
