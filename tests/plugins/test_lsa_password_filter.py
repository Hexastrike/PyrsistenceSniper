"""Tests for the LsaPasswordFilter declarative plugin (T1556.002).

SYSTEM hive, named value Notification Packages, HKLM scope,
controlset placeholder, allow filter for 'scecli'.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1556.lsa_password_filter import LsaPasswordFilter

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SYSTEM_HIVE = "/fake/SYSTEM"


def test_lsa_password_filter_happy_path(tmp_path: Path) -> None:
    """Non-default notification package produces a finding (not 'scecli')."""
    node = make_node(values={"Notification Packages": "evil_filter.dll"})
    plugin = make_plugin(LsaPasswordFilter, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)

    findings = plugin.run()
    assert len(findings) == 1, "Expected one finding for non-default filter DLL"
    assert findings[0].value == "evil_filter.dll", (
        "Finding value should be the filter DLL"
    )
    assert findings[0].path.startswith("HKLM\\SYSTEM"), (
        "Path should begin with HKLM\\SYSTEM"
    )


def test_lsa_password_filter_empty_registry(tmp_path: Path) -> None:
    """Empty registry node produces no findings."""
    node = make_node()
    plugin = make_plugin(LsaPasswordFilter, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)

    findings = plugin.run()
    assert findings == [], "Empty registry node should produce no findings"


def test_lsa_password_filter_missing_hive(tmp_path: Path) -> None:
    """Missing SYSTEM hive produces no findings."""
    plugin = make_plugin(LsaPasswordFilter, tmp_path)
    plugin.context.hive_path.return_value = None

    findings = plugin.run()
    assert findings == [], "Missing hive should produce no findings"


def test_lsa_password_filter_multiple_values(tmp_path: Path) -> None:
    """REG_MULTI_SZ with multiple non-default packages produces multiple findings."""
    node = make_node(
        values={
            "Notification Packages": ["evil1.dll", "evil2.dll"],
        }
    )
    plugin = make_plugin(LsaPasswordFilter, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)

    findings = plugin.run()
    assert len(findings) == 2, "Expected two findings for two filter DLLs"
    values = {f.value for f in findings}
    assert values == {"evil1.dll", "evil2.dll"}, "Both filter DLLs should be reported"
