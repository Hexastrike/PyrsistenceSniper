"""Tests for the ShellLauncher declarative plugin (T1547.001).

SOFTWARE hive, named value Shell, 2 HKLM targets,
allow filter for 'sys:' prefix.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1547.shell_launcher import ShellLauncher

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SOFTWARE_HIVE = "/fake/SOFTWARE"


def test_shell_launcher_happy_path(tmp_path: Path) -> None:
    """Non-default Shell value produces a finding (not 'sys:' prefix)."""
    node = make_node(values={"Shell": r"C:\evil.exe"})
    plugin = make_plugin(ShellLauncher, tmp_path)
    setup_hklm(plugin, node, hive_path=_SOFTWARE_HIVE)

    findings = plugin.run()
    assert len(findings) >= 1, "Expected at least one finding for non-default Shell"
    hklm_findings = [f for f in findings if f.path.startswith("HKLM")]
    assert any(f.value == r"C:\evil.exe" for f in hklm_findings), (
        "At least one finding should have the evil Shell value"
    )


def test_shell_launcher_empty_registry(tmp_path: Path) -> None:
    """Empty registry node produces no findings."""
    node = make_node()
    plugin = make_plugin(ShellLauncher, tmp_path)
    setup_hklm(plugin, node, hive_path=_SOFTWARE_HIVE)

    findings = plugin.run()
    assert findings == [], "Empty registry should produce no findings"


def test_shell_launcher_missing_hive(tmp_path: Path) -> None:
    """Missing SOFTWARE hive produces no findings."""
    plugin = make_plugin(ShellLauncher, tmp_path)
    plugin.context.hive_path.return_value = None

    findings = plugin.run()
    assert findings == [], "Missing hive should produce no findings"


def test_shell_launcher_multiple_values(tmp_path: Path) -> None:
    """Shell value plus extra values only matches Shell (named value)."""
    node = make_node(
        values={
            "Shell": r"C:\evil.exe",
            "OtherValue": "benign.exe",
        }
    )
    plugin = make_plugin(ShellLauncher, tmp_path)
    setup_hklm(plugin, node, hive_path=_SOFTWARE_HIVE)

    findings = plugin.run()
    hklm_findings = [f for f in findings if f.path.startswith("HKLM")]
    # 2 targets both matching Shell, so expect 2 findings
    assert len(hklm_findings) == 2, (
        "Expected two HKLM findings for two targets with Shell value"
    )
    assert all(f.value == r"C:\evil.exe" for f in hklm_findings), (
        "All findings should have the Shell value, not OtherValue"
    )
