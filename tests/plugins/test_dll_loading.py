"""Tests for all 19 DLL loading plugins in T1574/dll_loading.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from pyrsistencesniper.plugins.T1574.dll_loading import (
    AutodialDll,
    ChmHelper,
    CryptoExpoOffload,
    DiagTrackDll,
    DiagTrackListenerDll,
    Direct3dDll,
    GpExtensionDlls,
    HhctrlOcx,
    KnownManagedDebuggingDlls,
    LsaExtensions,
    Mapi32DllPath,
    MiniDumpAuxiliaryDlls,
    MsdtcXaDll,
    NaturalLanguageDevelopmentPlatform,
    RdpTestDvcPlugin,
    SearchIndexerDll,
    ServerLevelPluginDll,
    WinsockAutoProxy,
    WuServiceStartupDll,
)

from .conftest import make_node, make_plugin, setup_hklm

# ---------------------------------------------------------------------------
# Parametrized tests for the 16 declarative plugins
# ---------------------------------------------------------------------------

_DECLARATIVE_CASES: list[tuple[type, str, str, str]] = [
    (
        NaturalLanguageDevelopmentPlatform,
        "DllOverridePath",
        r"C:\evil.dll",
        "/fake/SOFTWARE",
    ),
    (ChmHelper, "Location", r"C:\evil_chm.dll", "/fake/SOFTWARE"),
    (HhctrlOcx, "(Default)", r"C:\evil_hhctrl.dll", "/fake/SOFTWARE"),
    (AutodialDll, "AutodialDLL", r"C:\evil_autodial.dll", "/fake/SYSTEM"),
    (LsaExtensions, "Extensions", r"evil_lsa.dll", "/fake/SYSTEM"),
    (ServerLevelPluginDll, "ServerLevelPluginDll", r"C:\evil_dns.dll", "/fake/SYSTEM"),
    (CryptoExpoOffload, "ExpoOffload", r"C:\evil_crypto.dll", "/fake/SOFTWARE"),
    (Direct3dDll, "SoftwareRasterizer", r"C:\evil_d3d.dll", "/fake/SOFTWARE"),
    (MsdtcXaDll, "OracleXaLib", r"evil_xa.dll", "/fake/SOFTWARE"),
    (DiagTrackDll, "ImagePath", r"C:\evil_diag.exe", "/fake/SYSTEM"),
    (DiagTrackListenerDll, "FileName", r"C:\evil_listener.etl", "/fake/SYSTEM"),
    (RdpTestDvcPlugin, "TestDVCPlugin", r"C:\evil_rdp.dll", "/fake/SOFTWARE"),
    (SearchIndexerDll, "DllPath", r"C:\evil_search.dll", "/fake/SOFTWARE"),
    (WuServiceStartupDll, "ServiceDll", r"C:\evil_wu.dll", "/fake/SYSTEM"),
    (
        KnownManagedDebuggingDlls,
        "KnownManagedDebuggingDlls",
        r"C:\evil_dbg.dll",
        "/fake/SOFTWARE",
    ),
    (Mapi32DllPath, "DLLPath", r"C:\evil_mapi.dll", "/fake/SOFTWARE"),
]


@pytest.mark.parametrize(
    ("plugin_cls", "value_key", "value_data", "hive_path"),
    _DECLARATIVE_CASES,
    ids=[c[0].__name__ for c in _DECLARATIVE_CASES],
)
def test_declarative_happy_path(
    tmp_path: Path,
    plugin_cls: type,
    value_key: str,
    value_data: str,
    hive_path: str,
) -> None:
    """Each declarative plugin produces a finding when its registry value is present."""
    node = make_node(values={value_key: value_data})
    p = make_plugin(plugin_cls, tmp_path)
    setup_hklm(p, node, hive_path=hive_path)
    findings = p.run()
    assert len(findings) >= 1
    assert any(value_data in f.value for f in findings)
    assert all("T1574" in f.mitre_id for f in findings)


# ---------------------------------------------------------------------------
# TestMiniDumpAuxiliaryDlls -- custom run() plugin
# ---------------------------------------------------------------------------


class TestMiniDumpAuxiliaryDlls:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={r"C:\evil_minidump.dll": "1"})
        p = make_plugin(MiniDumpAuxiliaryDlls, tmp_path)
        setup_hklm(p, node, hive_path="/fake/SOFTWARE")
        findings = p.run()
        assert len(findings) >= 1
        assert any("evil_minidump.dll" in f.value for f in findings)
        assert all("T1574" in f.mitre_id for f in findings)

    def test_empty_name_skipped(self, tmp_path: Path) -> None:
        node = make_node(values={"  ": "1"})
        p = make_plugin(MiniDumpAuxiliaryDlls, tmp_path)
        setup_hklm(p, node, hive_path="/fake/SOFTWARE")
        findings = p.run()
        assert findings == []


# ---------------------------------------------------------------------------
# TestGpExtensionDlls -- custom run() plugin
# ---------------------------------------------------------------------------


class TestGpExtensionDlls:
    def test_happy_path(self, tmp_path: Path) -> None:
        child = make_node(values={"DllName": r"C:\evil_gp.dll"})
        tree = make_node(children={"{evil-guid}": child})
        p = make_plugin(GpExtensionDlls, tmp_path)
        setup_hklm(p, tree, hive_path="/fake/SOFTWARE")
        findings = p.run()
        assert len(findings) >= 1
        assert any("evil_gp.dll" in f.value for f in findings)
        assert all("T1574" in f.mitre_id for f in findings)

    def test_child_without_dllname_skipped(self, tmp_path: Path) -> None:
        child = make_node(values={"OtherValue": "irrelevant"})
        tree = make_node(children={"{some-guid}": child})
        p = make_plugin(GpExtensionDlls, tmp_path)
        setup_hklm(p, tree, hive_path="/fake/SOFTWARE")
        findings = p.run()
        assert findings == []


# ---------------------------------------------------------------------------
# TestWinsockAutoProxy -- custom run() plugin
# ---------------------------------------------------------------------------


class TestWinsockAutoProxy:
    def test_happy_path(self, tmp_path: Path) -> None:
        child = make_node(values={"LibraryPath": r"C:\evil_winsock.dll"})
        tree = make_node(children={"000000000001": child})
        p = make_plugin(WinsockAutoProxy, tmp_path)
        setup_hklm(p, tree, hive_path="/fake/SYSTEM")
        findings = p.run()
        assert len(findings) >= 1
        assert any("evil_winsock.dll" in f.value for f in findings)
        assert all("T1574" in f.mitre_id for f in findings)

    def test_child_without_librarypath_skipped(self, tmp_path: Path) -> None:
        child = make_node(values={"OtherValue": "irrelevant"})
        tree = make_node(children={"000000000001": child})
        p = make_plugin(WinsockAutoProxy, tmp_path)
        setup_hklm(p, tree, hive_path="/fake/SYSTEM")
        findings = p.run()
        assert findings == []
