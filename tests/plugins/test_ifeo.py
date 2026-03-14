from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1546.ifeo import (
    IfeoDebugger,
    IfeoDelegatedNtdll,
    IfeoSilentProcessExit,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


# --- IfeoDebugger ---


class TestIfeoDebugger:
    def test_happy_path(self, tmp_path: Path) -> None:
        child = make_node(name="notepad.exe", values={"Debugger": "evil.exe"})
        tree = make_node(children={"notepad.exe": child})
        p = make_plugin(IfeoDebugger, tmp_path)
        setup_hklm(p, tree)
        findings = p.run()
        assert len(findings) == 1
        assert findings[0].value == "evil.exe"
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_no_debugger_value(self, tmp_path: Path) -> None:
        child = make_node(name="notepad.exe", values={"SomeOther": "val"})
        tree = make_node(children={"notepad.exe": child})
        p = make_plugin(IfeoDebugger, tmp_path)
        setup_hklm(p, tree)
        assert p.run() == []

    def test_multiple_subkeys(self, tmp_path: Path) -> None:
        c1 = make_node(name="a.exe", values={"Debugger": "bad1.exe"})
        c2 = make_node(name="b.exe", values={"Debugger": "bad2.exe"})
        tree = make_node(children={"a.exe": c1, "b.exe": c2})
        p = make_plugin(IfeoDebugger, tmp_path)
        setup_hklm(p, tree)
        assert len(p.run()) == 2


# --- IfeoSilentProcessExit ---


class TestIfeoSilentProcessExit:
    def test_happy_path(self, tmp_path: Path) -> None:
        child = make_node(name="calc.exe", values={"MonitorProcess": "backdoor.exe"})
        tree = make_node(children={"calc.exe": child})
        p = make_plugin(IfeoSilentProcessExit, tmp_path)
        setup_hklm(p, tree)
        findings = p.run()
        assert len(findings) == 1
        assert "backdoor.exe" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_no_monitor_process(self, tmp_path: Path) -> None:
        child = make_node(name="calc.exe", values={"Other": "val"})
        tree = make_node(children={"calc.exe": child})
        p = make_plugin(IfeoSilentProcessExit, tmp_path)
        setup_hklm(p, tree)
        assert p.run() == []


# --- IfeoDelegatedNtdll ---


class TestIfeoDelegatedNtdll:
    def test_happy_path_flag_0x100(self, tmp_path: Path) -> None:
        child = make_node(
            name="target.exe",
            values={"VerifierDlls": "evil.dll", "GlobalFlag": 0x100},
        )
        tree = make_node(children={"target.exe": child})
        p = make_plugin(IfeoDelegatedNtdll, tmp_path)
        setup_hklm(p, tree)
        findings = p.run()
        assert len(findings) == 1
        assert findings[0].value == "evil.dll"
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_globalflag_combined_bits(self, tmp_path: Path) -> None:
        """GlobalFlag with 0x100 bit set among other flags should still match."""
        child = make_node(
            name="target.exe",
            values={"VerifierDlls": "evil.dll", "GlobalFlag": 0x300},
        )
        tree = make_node(children={"target.exe": child})
        p = make_plugin(IfeoDelegatedNtdll, tmp_path)
        setup_hklm(p, tree)
        assert len(p.run()) == 1

    def test_globalflag_zero_no_match(self, tmp_path: Path) -> None:
        """GlobalFlag without FLG_APPLICATION_VERIFIER yields nothing."""
        child = make_node(
            name="target.exe",
            values={"VerifierDlls": "evil.dll", "GlobalFlag": 0},
        )
        tree = make_node(children={"target.exe": child})
        p = make_plugin(IfeoDelegatedNtdll, tmp_path)
        setup_hklm(p, tree)
        assert p.run() == []

    def test_globalflag_wrong_bit(self, tmp_path: Path) -> None:
        """GlobalFlag with only 0x200 (not 0x100) yields nothing."""
        child = make_node(
            name="target.exe",
            values={"VerifierDlls": "evil.dll", "GlobalFlag": 0x200},
        )
        tree = make_node(children={"target.exe": child})
        p = make_plugin(IfeoDelegatedNtdll, tmp_path)
        setup_hklm(p, tree)
        assert p.run() == []

    def test_no_verifier_dlls(self, tmp_path: Path) -> None:
        child = make_node(name="target.exe", values={"GlobalFlag": 0x100})
        tree = make_node(children={"target.exe": child})
        p = make_plugin(IfeoDelegatedNtdll, tmp_path)
        setup_hklm(p, tree)
        assert p.run() == []

    def test_globalflag_not_int(self, tmp_path: Path) -> None:
        """Non-integer GlobalFlag should not match."""
        child = make_node(
            name="target.exe",
            values={"VerifierDlls": "evil.dll", "GlobalFlag": "notanint"},
        )
        tree = make_node(children={"target.exe": child})
        p = make_plugin(IfeoDelegatedNtdll, tmp_path)
        setup_hklm(p, tree)
        assert p.run() == []
