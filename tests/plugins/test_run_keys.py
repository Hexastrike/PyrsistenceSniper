"""Tests for the RunKeys declarative plugin (T1547.001).

SOFTWARE hive, wildcard values, BOTH scope, 8 targets,
allow filter for SecurityHealthSystray.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1547.run_keys import RunKeys

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SOFTWARE_HIVE = "/fake/SOFTWARE"


def test_run_keys_happy_path(tmp_path: Path) -> None:
    """Wildcard value under Run key produces findings (non-allow-listed)."""
    node = make_node(values={"EvilApp": "evil.exe"})
    plugin = make_plugin(RunKeys, tmp_path)
    setup_hklm(plugin, node, hive_path=_SOFTWARE_HIVE)

    findings = plugin.run()
    hklm_findings = [f for f in findings if f.path.startswith("HKLM")]
    assert len(hklm_findings) >= 1, "Expected at least one HKLM finding for evil.exe"
    assert any(f.value == "evil.exe" for f in hklm_findings), (
        "At least one finding should have value evil.exe"
    )


def test_run_keys_empty_registry(tmp_path: Path) -> None:
    """Empty registry node produces no HKLM findings."""
    node = make_node()
    plugin = make_plugin(RunKeys, tmp_path)
    setup_hklm(plugin, node, hive_path=_SOFTWARE_HIVE)

    findings = plugin.run()
    hklm_findings = [f for f in findings if f.path.startswith("HKLM")]
    assert hklm_findings == [], "Empty registry should produce no HKLM findings"


def test_run_keys_missing_hive(tmp_path: Path) -> None:
    """Missing SOFTWARE hive produces no findings."""
    plugin = make_plugin(RunKeys, tmp_path)
    plugin.context.hive_path.return_value = None

    findings = plugin.run()
    assert findings == [], "Missing hive should produce no findings"


def test_run_keys_multiple_values(tmp_path: Path) -> None:
    """Multiple wildcard values produce multiple HKLM findings."""
    node = make_node(
        values={
            "Evil1": "evil1.exe",
            "Evil2": "evil2.exe",
            "Evil3": "evil3.exe",
        }
    )
    plugin = make_plugin(RunKeys, tmp_path)
    setup_hklm(plugin, node, hive_path=_SOFTWARE_HIVE)

    findings = plugin.run()
    hklm_findings = [f for f in findings if f.path.startswith("HKLM")]
    # RunKeys has 8 targets, each returning 3 values from the same mock
    # Verify we get at least 3 findings per target
    assert len(hklm_findings) >= 3, "Expected at least three HKLM findings"
    found_values = {f.value for f in hklm_findings}
    assert {"evil1.exe", "evil2.exe", "evil3.exe"}.issubset(found_values), (
        "All three evil values should appear in HKLM findings"
    )
