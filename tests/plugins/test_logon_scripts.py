"""Tests for the LogonScripts declarative plugin (T1037.001).

NTUSER hive, named value UserInitMprLogonScript, HKU scope.
Requires user_profiles with ntuser_path for hive access.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import UserProfile
from pyrsistencesniper.plugins.T1037.logon_scripts import LogonScripts

from .conftest import make_node, make_plugin

if TYPE_CHECKING:
    pass


def test_logon_scripts_happy_path(tmp_path: Path) -> None:
    """User profile with UserInitMprLogonScript produces a finding."""
    profiles = [
        UserProfile(
            "victim",
            tmp_path / "Users" / "victim",
            tmp_path / "Users" / "victim" / "NTUSER.DAT",
        ),
    ]
    plugin = make_plugin(LogonScripts, tmp_path, user_profiles=profiles)
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = make_node(
        values={"UserInitMprLogonScript": "evil.bat"}
    )

    findings = plugin.run()
    assert len(findings) == 1, "Expected exactly one finding for logon script"
    assert findings[0].value == "evil.bat", "Finding value should be the logon script"
    assert findings[0].path.startswith("HKU\\victim"), (
        "Path should reference the user profile"
    )


def test_logon_scripts_empty_registry(tmp_path: Path) -> None:
    """User profile with empty registry node produces no findings."""
    profiles = [
        UserProfile(
            "victim",
            tmp_path / "Users" / "victim",
            tmp_path / "Users" / "victim" / "NTUSER.DAT",
        ),
    ]
    plugin = make_plugin(LogonScripts, tmp_path, user_profiles=profiles)
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = make_node()

    findings = plugin.run()
    assert findings == [], "Empty registry node should produce no findings"


def test_logon_scripts_missing_hive(tmp_path: Path) -> None:
    """No user profiles produces no findings."""
    plugin = make_plugin(LogonScripts, tmp_path, user_profiles=[])

    findings = plugin.run()
    assert findings == [], "No user profiles should produce no findings"


def test_logon_scripts_multiple_values(tmp_path: Path) -> None:
    """Multiple user profiles each with logon scripts produce multiple findings."""
    profiles = [
        UserProfile(
            "alice",
            tmp_path / "Users" / "alice",
            tmp_path / "Users" / "alice" / "NTUSER.DAT",
        ),
        UserProfile(
            "bob",
            tmp_path / "Users" / "bob",
            tmp_path / "Users" / "bob" / "NTUSER.DAT",
        ),
    ]
    plugin = make_plugin(LogonScripts, tmp_path, user_profiles=profiles)

    hive_a = MagicMock()
    hive_b = MagicMock()
    plugin.registry.open_hive.side_effect = [hive_a, hive_b]
    plugin.registry.load_subtree.side_effect = [
        make_node(values={"UserInitMprLogonScript": "evil_a.bat"}),
        make_node(values={"UserInitMprLogonScript": "evil_b.bat"}),
    ]

    findings = plugin.run()
    assert len(findings) == 2, "Expected two findings for two user profiles"
    values = {f.value for f in findings}
    assert values == {"evil_a.bat", "evil_b.bat"}, (
        "Both logon scripts should be reported"
    )
    assert findings[0].path.startswith("HKU\\alice"), (
        "First finding should reference alice"
    )
    assert findings[1].path.startswith("HKU\\bob"), (
        "Second finding should reference bob"
    )
