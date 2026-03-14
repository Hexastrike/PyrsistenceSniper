"""Tests for the DotNetStartupHooks plugin in T1574/dotnet_startup_hooks.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1574.dotnet_startup_hooks import DotNetStartupHooks

from .conftest import make_node, make_plugin


def test_system_env_hook_detected(tmp_path: Path) -> None:
    """DOTNET_STARTUP_HOOKS in SYSTEM environment produces a SYSTEM finding."""
    env_node = make_node(values={"DOTNET_STARTUP_HOOKS": r"C:\evil_hook.dll"})
    p = make_plugin(DotNetStartupHooks, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SYSTEM")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.return_value = env_node
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil_hook.dll" in f.value for f in findings)
    assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)
    assert all("T1574" in f.mitre_id for f in findings)


def test_env_key_without_hook_value(tmp_path: Path) -> None:
    """Environment key exists but DOTNET_STARTUP_HOOKS is absent -- no findings."""
    env_node = make_node(values={"PATH": r"C:\Windows"})
    p = make_plugin(DotNetStartupHooks, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SYSTEM")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.return_value = env_node
    findings = p.run()
    assert findings == []
