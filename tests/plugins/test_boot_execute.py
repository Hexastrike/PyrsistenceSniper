from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import Finding, MatchResult
from pyrsistencesniper.plugins.T1547.boot_execute import (
    BootExecute,
    PlatformExecute,
    S0InitialCommand,
    ServiceControlManagerExtension,
    SessionManagerExecute,
    SessionManagerSubSystems,
    SetupExecute,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SYSTEM_HIVE = "/fake/SYSTEM"


def test_boot_execute_happy(tmp_path: Path) -> None:
    node = make_node(values={"BootExecute": "evil.exe"})
    plugin = make_plugin(BootExecute, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert "evil.exe" in findings[0].value


def test_setup_execute_happy(tmp_path: Path) -> None:
    node = make_node(values={"SetupExecute": "setup_evil.exe"})
    plugin = make_plugin(SetupExecute, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert "setup_evil.exe" in findings[0].value


def test_platform_execute_happy(tmp_path: Path) -> None:
    node = make_node(values={"PlatformExecute": "plat_evil.exe"})
    plugin = make_plugin(PlatformExecute, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert "plat_evil.exe" in findings[0].value


def test_session_manager_execute_happy(tmp_path: Path) -> None:
    node = make_node(values={"Execute": "smexec.exe"})
    plugin = make_plugin(SessionManagerExecute, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert "smexec.exe" in findings[0].value


def test_s0_initial_command_happy(tmp_path: Path) -> None:
    node = make_node(values={"S0InitialCommand": "s0cmd.exe"})
    plugin = make_plugin(S0InitialCommand, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert "s0cmd.exe" in findings[0].value


def test_scm_extension_happy(tmp_path: Path) -> None:
    node = make_node(values={"evil_dll": "C:\\evil.dll"})
    plugin = make_plugin(ServiceControlManagerExtension, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert "evil.dll" in findings[0].value


def test_session_manager_subsystems_happy(tmp_path: Path) -> None:
    node = make_node(values={"Windows": r"%SystemRoot%\system32\evil.exe"})
    plugin = make_plugin(SessionManagerSubSystems, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert "evil.exe" in findings[0].value


def test_session_manager_subsystems_empty(tmp_path: Path) -> None:
    node = make_node()
    plugin = make_plugin(SessionManagerSubSystems, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    assert plugin.run() == []


class TestSubSystemsFilterRule:
    """Tests for the fixed csrss.exe value_matches + signer FilterRule (allow[0])."""

    rule = SessionManagerSubSystems.definition.allow[0]

    def test_csrss_signed_full(self) -> None:
        f = Finding(
            value=r"%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows",
            signer="Microsoft Windows",
        )
        assert self.rule.match_result(f) == MatchResult.FULL

    def test_csrss_unsigned_partial(self) -> None:
        f = Finding(
            value=r"%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows",
            signer="",
        )
        assert self.rule.match_result(f) == MatchResult.PARTIAL

    def test_evil_exe_none(self) -> None:
        f = Finding(value=r"%SystemRoot%\system32\evil.exe", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.NONE
