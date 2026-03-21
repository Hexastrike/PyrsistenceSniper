"""Tests for the DotNetStartupHooks plugin (T1574.012).

Detects DOTNET_STARTUP_HOOKS in SYSTEM environment and per-user HKU environment.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1574.dotnet_startup_hooks import DotNetStartupHooks

from .conftest import make_deps, make_node


def _make_plugin(
    tmp_path: Path,
    user_profiles: list[UserProfile] | None = None,
) -> DotNetStartupHooks:
    context, _registry, _fs, _profile = make_deps(tmp_path, user_profiles=user_profiles)
    return DotNetStartupHooks(context=context)


def test_system_hive_detected(tmp_path: Path) -> None:
    """DOTNET_STARTUP_HOOKS in SYSTEM environment produces a SYSTEM finding."""
    plugin = _make_plugin(tmp_path)
    node = make_node(values={"DOTNET_STARTUP_HOOKS": r"C:\evil.dll"})

    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = node

    findings = plugin.run()
    system_findings = [f for f in findings if f.access_gained == AccessLevel.SYSTEM]
    assert len(system_findings) == 1
    assert system_findings[0].value == r"C:\evil.dll"
    assert "DOTNET_STARTUP_HOOKS" in system_findings[0].path


def test_system_hive_missing(tmp_path: Path) -> None:
    """Missing SYSTEM hive produces no findings."""
    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = None

    findings = plugin.run()
    assert findings == []


def test_system_env_key_missing(tmp_path: Path) -> None:
    """SYSTEM hive exists but Environment key is absent."""
    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = None

    findings = plugin.run()
    assert findings == []


def test_system_env_no_hooks_value(tmp_path: Path) -> None:
    """Environment key exists but DOTNET_STARTUP_HOOKS is not set."""
    plugin = _make_plugin(tmp_path)
    node = make_node(values={"OTHER_VAR": "something"})
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = node

    findings = plugin.run()
    assert findings == []


def test_user_hive_detected(tmp_path: Path) -> None:
    """DOTNET_STARTUP_HOOKS in a user hive produces a USER finding."""
    profiles = [
        UserProfile("victim", tmp_path / "Users" / "victim", tmp_path / "NTUSER.DAT"),
    ]
    plugin = _make_plugin(tmp_path, user_profiles=profiles)

    system_hive = MagicMock()
    user_hive = MagicMock()
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.side_effect = [system_hive, user_hive]
    plugin.registry.load_subtree.side_effect = [
        None,  # SYSTEM Environment — no hooks
        make_node(values={"DOTNET_STARTUP_HOOKS": r"C:\user_evil.dll"}),
    ]

    findings = plugin.run()
    user_findings = [f for f in findings if f.access_gained == AccessLevel.USER]
    assert len(user_findings) == 1
    assert user_findings[0].value == r"C:\user_evil.dll"
    assert "victim" in user_findings[0].path


def test_both_system_and_user(tmp_path: Path) -> None:
    """Hooks in both SYSTEM and user hives produce findings for each."""
    profiles = [
        UserProfile("alice", tmp_path / "Users" / "alice", tmp_path / "NTUSER.DAT"),
    ]
    plugin = _make_plugin(tmp_path, user_profiles=profiles)

    system_hive = MagicMock()
    user_hive = MagicMock()
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.side_effect = [system_hive, user_hive]
    plugin.registry.load_subtree.side_effect = [
        make_node(values={"DOTNET_STARTUP_HOOKS": r"C:\sys.dll"}),
        make_node(values={"DOTNET_STARTUP_HOOKS": r"C:\user.dll"}),
    ]

    findings = plugin.run()
    assert len(findings) == 2
    access_levels = {f.access_gained for f in findings}
    assert access_levels == {AccessLevel.SYSTEM, AccessLevel.USER}
