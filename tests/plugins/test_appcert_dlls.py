"""Tests for the AppCertDlls declarative plugin (T1546.009).

SYSTEM hive, wildcard values, HKLM scope, controlset placeholder.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1546.appcert_dlls import AppCertDlls

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SYSTEM_HIVE = "/fake/SYSTEM"


def test_appcert_dlls_happy_path(tmp_path: Path) -> None:
    """Wildcard value under controlset key produces a finding."""
    node = make_node(values={"evil.dll": r"C:\evil.dll"})
    plugin = make_plugin(AppCertDlls, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)

    findings = plugin.run()
    assert len(findings) == 1, "Expected exactly one finding for a single evil DLL"
    assert r"C:\evil.dll" in findings[0].value, (
        "Finding value should contain the DLL path"
    )
    assert findings[0].path.startswith("HKLM\\SYSTEM"), (
        "Path should begin with HKLM\\SYSTEM"
    )


def test_appcert_dlls_empty_registry(tmp_path: Path) -> None:
    """Empty registry node produces no findings."""
    node = make_node()
    plugin = make_plugin(AppCertDlls, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)

    findings = plugin.run()
    assert findings == [], "Empty registry node should produce no findings"


def test_appcert_dlls_missing_hive(tmp_path: Path) -> None:
    """Missing SYSTEM hive produces no findings."""
    plugin = make_plugin(AppCertDlls, tmp_path)
    plugin.context.hive_path.return_value = None

    findings = plugin.run()
    assert findings == [], "Missing hive should produce no findings"


def test_appcert_dlls_multiple_values(tmp_path: Path) -> None:
    """Multiple wildcard values produce multiple findings."""
    node = make_node(
        values={
            "evil1.dll": r"C:\evil1.dll",
            "evil2.dll": r"C:\evil2.dll",
            "evil3.dll": r"C:\evil3.dll",
        }
    )
    plugin = make_plugin(AppCertDlls, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)

    findings = plugin.run()
    assert len(findings) == 3, "Expected three findings for three DLL entries"
    found_values = {f.value for f in findings}
    assert found_values == {r"C:\evil1.dll", r"C:\evil2.dll", r"C:\evil3.dll"}, (
        "All three DLL values should appear in findings"
    )
