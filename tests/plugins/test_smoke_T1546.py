from __future__ import annotations

import json as _json
from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel, UserProfile

from .conftest import make_node, make_plugin, setup_hklm


def test_ifeo_debugger(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.ifeo import IfeoDebugger

    child = make_node(name="notepad.exe", values={"Debugger": "evil.exe"})
    tree = make_node(children={"notepad.exe": child})
    p = make_plugin(IfeoDebugger, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert f.value == "evil.exe"
    assert f.access_gained == AccessLevel.SYSTEM
    assert "T1546" in f.mitre_id


def test_ifeo_silent_process_exit(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.ifeo import IfeoSilentProcessExit

    child = make_node(name="calc.exe", values={"MonitorProcess": "backdoor.exe"})
    tree = make_node(children={"calc.exe": child})
    p = make_plugin(IfeoSilentProcessExit, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "backdoor.exe" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_ifeo_delegated_ntdll(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.ifeo import IfeoDelegatedNtdll

    child = make_node(
        name="target.exe", values={"VerifierDlls": "evil.dll", "GlobalFlag": 0x100}
    )
    tree = make_node(children={"target.exe": child})
    p = make_plugin(IfeoDelegatedNtdll, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert f.value == "evil.dll"
    assert f.access_gained == AccessLevel.SYSTEM


def test_ifeo_delegated_ntdll_no_flag(tmp_path: Path) -> None:
    """GlobalFlag without FLG_APPLICATION_VERIFIER should yield nothing."""
    from pyrsistencesniper.plugins.T1546.ifeo import IfeoDelegatedNtdll

    child = make_node(
        name="target.exe", values={"VerifierDlls": "evil.dll", "GlobalFlag": 0}
    )
    tree = make_node(children={"target.exe": child})
    p = make_plugin(IfeoDelegatedNtdll, tmp_path)
    setup_hklm(p, tree)
    assert p.run() == []


def test_com_treat_as(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.com_hijack import ComTreatAs

    treat_as_node = make_node(name="TreatAs", values={"(Default)": "{evil-clsid}"})
    clsid_node = make_node(name="{abc}", children={"TreatAs": treat_as_node})
    tree = make_node(children={"{abc}": clsid_node})
    p = make_plugin(ComTreatAs, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "{evil-clsid}" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_disk_cleanup_handler(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.disk_cleanup import DiskCleanupHandler

    handler_node = make_node(name="OldFiles", values={"(Default)": "{CLSID-1}"})
    tree = make_node(children={"OldFiles": handler_node})
    inproc_node = make_node(name="InprocServer32", values={"(Default)": "C:\\evil.dll"})

    p = make_plugin(DiskCleanupHandler, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.side_effect = [tree, inproc_node]

    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.dll" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_appinit_dlls(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.appinit_dlls import AppInitDlls

    node = make_node(
        values={
            "AppInit_DLLs": "C:\\evil.dll C:\\bad.dll",
            "LoadAppInit_DLLs": 1,
            "RequireSignedAppInit_DLLs": 0,
        }
    )
    p = make_plugin(AppInitDlls, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.side_effect = [node, None]

    findings = p.run()
    assert len(findings) == 2
    assert any("evil.dll" in f.value for f in findings)
    assert any("LoadAppInit_DLLs=1" in f.value for f in findings)
    assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)


def test_screensaver(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.screensaver import Screensaver

    profiles = [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]
    p = make_plugin(Screensaver, tmp_path, user_profiles=profiles)
    ntuser = MagicMock()
    p.registry.open_hive.return_value = ntuser
    node = make_node(values={"SCRNSAVE.EXE": "C:\\evil.scr"})
    p.registry.load_subtree.return_value = node

    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.scr" in f.value
    assert f.access_gained == AccessLevel.USER


def test_assistive_technology_at_registration(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.assistive_technology import AssistiveTechnology

    at_child = make_node(name="EvilAT", values={"StartExe": "C:\\evil\\at.exe"})
    tree = make_node(children={"EvilAT": at_child})
    p = make_plugin(AssistiveTechnology, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) >= 1
    assert any("at.exe" in f.value for f in findings)
    assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)


def test_assistive_technology_user_config(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.assistive_technology import AssistiveTechnology

    profiles = [
        UserProfile(
            username="victim",
            profile_path=Path("/Users/victim"),
            ntuser_path=Path("/Users/victim/NTUSER.DAT"),
        ),
    ]
    p = make_plugin(AssistiveTechnology, tmp_path, user_profiles=profiles)
    p.context.hive_path.return_value = None
    ntuser = MagicMock()
    p.registry.open_hive.return_value = ntuser
    config_node = make_node(values={"Configuration": "EvilAT,CustomHelper"})
    p.registry.load_subtree.return_value = config_node

    findings = p.run()
    assert len(findings) == 2
    assert all(f.access_gained == AccessLevel.USER for f in findings)


def test_amsi_providers(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.amsi_providers import AmsiProviders

    clsid_child = make_node(name="{AAAA-BBBB}")
    tree = make_node(children={"{AAAA-BBBB}": clsid_child})
    p = make_plugin(AmsiProviders, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    inproc_node = make_node(values={"(Default)": "C:\\evil_amsi.dll"})
    p.registry.load_subtree.side_effect = [tree, inproc_node]
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil_amsi.dll" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_app_paths(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.app_paths import AppPaths

    child = make_node(name="evil.exe", values={"(Default)": "C:\\malware\\evil.exe"})
    tree = make_node(children={"evil.exe": child})
    p = make_plugin(AppPaths, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.exe" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_telemetry_controller(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.telemetry_controller import (
        TelemetryController,
    )

    child = make_node(name="EvilCtrl", values={"Command": "C:\\evil.exe"})
    tree = make_node(children={"EvilCtrl": child})
    p = make_plugin(TelemetryController, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.exe" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_power_automate(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.power_automate import PowerAutomate

    profiles = [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]
    p = make_plugin(PowerAutomate, tmp_path, user_profiles=profiles)
    flows_dir = (
        tmp_path
        / "Users"
        / "user1"
        / "AppData"
        / "Local"
        / "Microsoft"
        / "Power Automate Desktop"
        / "Flows"
    )
    evil_flow = flows_dir / "EvilFlow"
    evil_flow.mkdir(parents=True)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert f.value == "EvilFlow"
    assert f.access_gained == AccessLevel.USER


def test_wer_runtime_exception(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.debugger_hijacking import (
        WerRuntimeExceptionHelperModules,
    )

    tree = make_node(values={"C:\\evil\\helper.dll": 0})
    p = make_plugin(WerRuntimeExceptionHelperModules, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "helper.dll" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_accessibility_tools(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.accessibility_tools import AccessibilityTools

    p = make_plugin(AccessibilityTools, tmp_path)
    cmd_dir = tmp_path / "Windows" / "System32"
    cmd_dir.mkdir(parents=True)
    (cmd_dir / "cmd.exe").write_bytes(b"fake-cmd-content")
    (cmd_dir / "sethc.exe").write_bytes(b"fake-cmd-content")
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "sethc.exe" in f.path
    assert f.access_gained == AccessLevel.SYSTEM


def test_windows_terminal(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.windows_terminal import WindowsTerminal

    profiles = [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]
    p = make_plugin(WindowsTerminal, tmp_path, user_profiles=profiles)
    settings_dir = (
        tmp_path
        / "Users"
        / "user1"
        / "AppData"
        / "Local"
        / "Packages"
        / "Microsoft.WindowsTerminal_8wekyb3d8bbwe"
        / "LocalState"
    )
    settings_dir.mkdir(parents=True)
    data = {"profiles": {"list": [{"commandline": "C:\\evil\\shell.exe"}]}}
    (settings_dir / "settings.json").write_text(_json.dumps(data), encoding="utf-8")
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil" in f.value
    assert f.access_gained == AccessLevel.USER


def test_powershell_profiles(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.powershell_profiles import PowerShellProfiles

    p = make_plugin(PowerShellProfiles, tmp_path)
    ps_dir = tmp_path / "Windows" / "System32" / "WindowsPowerShell" / "v1.0"
    ps_dir.mkdir(parents=True)
    (ps_dir / "profile.ps1").write_text("evil-code")
    findings = p.run()
    assert len(findings) >= 1
    assert any("profile.ps1" in f.value for f in findings)
    assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)
