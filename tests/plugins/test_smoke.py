from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.image import UserProfile
from pyrsistencesniper.models.finding import AccessLevel

from .conftest import make_deps, make_node


def _plugin(
    cls: type,
    tmp_path: Path,
    *,
    user_profiles: list[UserProfile] | None = None,
) -> object:
    image, registry, filesystem, profile = make_deps(
        tmp_path, user_profiles=user_profiles
    )
    return cls(registry=registry, filesystem=filesystem, image=image, profile=profile)


def _setup_hklm(
    plugin: object,
    tree_node: object,
    *,
    hive_path: str = "/fake/SOFTWARE",
) -> None:
    plugin.image.hive_path.return_value = Path(hive_path)  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.return_value = tree_node  # type: ignore[union-attr]


# -- IFEO family ---------------------------------------------------------------


def test_ifeo_debugger(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.ifeo import IfeoDebugger

    child = make_node(name="notepad.exe", values={"Debugger": "evil.exe"})
    tree = make_node(children={"notepad.exe": child})
    p = _plugin(IfeoDebugger, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert findings[0].value == "evil.exe"


def test_ifeo_silent_process_exit(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.ifeo import IfeoSilentProcessExit

    child = make_node(name="calc.exe", values={"MonitorProcess": "backdoor.exe"})
    tree = make_node(children={"calc.exe": child})
    p = _plugin(IfeoSilentProcessExit, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "backdoor.exe" in findings[0].value


def test_ifeo_delegated_ntdll(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.ifeo import IfeoDelegatedNtdll

    child = make_node(
        name="target.exe", values={"VerifierDlls": "evil.dll", "GlobalFlag": 0x100}
    )
    tree = make_node(children={"target.exe": child})
    p = _plugin(IfeoDelegatedNtdll, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert findings[0].value == "evil.dll"


def test_ifeo_delegated_ntdll_no_flag(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.ifeo import IfeoDelegatedNtdll

    child = make_node(
        name="target.exe", values={"VerifierDlls": "evil.dll", "GlobalFlag": 0}
    )
    tree = make_node(children={"target.exe": child})
    p = _plugin(IfeoDelegatedNtdll, tmp_path)
    _setup_hklm(p, tree)
    assert p.run() == []


# -- COM / CLSID ---------------------------------------------------------------


def test_com_treat_as(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.com_hijack import ComTreatAs

    treat_as_node = make_node(name="TreatAs", values={"(Default)": "{evil-clsid}"})
    clsid_node = make_node(name="{abc}", children={"TreatAs": treat_as_node})
    tree = make_node(children={"{abc}": clsid_node})
    p = _plugin(ComTreatAs, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "{evil-clsid}" in findings[0].value


def test_disk_cleanup_handler(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.disk_cleanup import DiskCleanupHandler

    handler_node = make_node(name="OldFiles", values={"(Default)": "{CLSID-1}"})
    tree = make_node(children={"OldFiles": handler_node})
    inproc_node = make_node(name="InprocServer32", values={"(Default)": "C:\\evil.dll"})

    p = _plugin(DiskCleanupHandler, tmp_path)
    p.image.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.side_effect = [tree, inproc_node]

    findings = p.run()
    assert len(findings) == 1
    assert "evil.dll" in findings[0].value


def test_explorer_context_menu(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.explorer_context_menu import (
        ExplorerContextMenu,
    )

    handler_node = make_node(name="EvilHandler", values={"(Default)": "{CLSID-X}"})
    tree = make_node(children={"EvilHandler": handler_node})

    p = _plugin(ExplorerContextMenu, tmp_path)
    p.image.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    # 3 context menu paths: tree for first, None for rest
    p.registry.load_subtree.side_effect = [tree, None, None, None]

    findings = p.run()
    assert len(findings) == 1


# -- Active Setup ---------------------------------------------------------------


def test_active_setup(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.active_setup import ActiveSetup

    child = make_node(name="{comp}", values={"StubPath": "C:\\evil\\setup.exe"})
    tree = make_node(children={"{comp}": child})
    p = _plugin(ActiveSetup, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "setup.exe" in findings[0].value


# -- AppInit DLLs ---------------------------------------------------------------


def test_appinit_dlls(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.appinit_dlls import AppInitDlls

    node = make_node(
        values={
            "AppInit_DLLs": "C:\\evil.dll C:\\bad.dll",
            "LoadAppInit_DLLs": 1,
            "RequireSignedAppInit_DLLs": 0,
        }
    )
    p = _plugin(AppInitDlls, tmp_path)
    p.image.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    # Two key paths (native + Wow64): return node for first, None for second
    p.registry.load_subtree.side_effect = [node, None]

    findings = p.run()
    assert len(findings) == 2
    assert any("evil.dll" in f.value for f in findings)
    assert any("LoadAppInit_DLLs=1" in f.value for f in findings)


# -- Screensaver ----------------------------------------------------------------


def test_screensaver(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.screensaver import Screensaver

    profiles = [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]
    p = _plugin(Screensaver, tmp_path, user_profiles=profiles)
    ntuser = MagicMock()
    p.registry.open_hive.return_value = ntuser
    node = make_node(values={"SCRNSAVE.EXE": "C:\\evil.scr"})
    p.registry.load_subtree.return_value = node

    findings = p.run()
    assert len(findings) == 1
    assert "evil.scr" in findings[0].value
    assert findings[0].access_gained == AccessLevel.USER


# -- Assistive Technology -------------------------------------------------------


def test_assistive_technology_at_registration(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.assistive_technology import AssistiveTechnology

    at_child = make_node(name="EvilAT", values={"StartExe": "C:\\evil\\at.exe"})
    tree = make_node(children={"EvilAT": at_child})
    p = _plugin(AssistiveTechnology, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) >= 1
    assert any("at.exe" in f.value for f in findings)


def test_assistive_technology_user_config(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.assistive_technology import AssistiveTechnology

    profiles = [
        UserProfile(
            username="victim",
            profile_path=Path("/Users/victim"),
            ntuser_path=Path("/Users/victim/NTUSER.DAT"),
        ),
    ]
    p = _plugin(AssistiveTechnology, tmp_path, user_profiles=profiles)
    p.image.hive_path.return_value = None  # no HKLM SOFTWARE
    ntuser = MagicMock()
    p.registry.open_hive.return_value = ntuser
    config_node = make_node(values={"Configuration": "EvilAT,CustomHelper"})
    p.registry.load_subtree.return_value = config_node

    findings = p.run()
    assert len(findings) == 2
    assert all(f.access_gained == AccessLevel.USER for f in findings)


# -- Services -------------------------------------------------------------------


def test_service_failure_command(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1543.service_failure_actions import (
        ServiceFailureCommand,
    )

    child = make_node(name="EvilSvc", values={"FailureCommand": "C:\\evil.exe"})
    tree = make_node(children={"EvilSvc": child})
    p = _plugin(ServiceFailureCommand, tmp_path)
    _setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1


def test_windows_service_image_path(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1543.windows_services import WindowsServiceImagePath

    child = make_node(name="Svc", values={"ImagePath": "C:\\svc.exe"})
    tree = make_node(children={"Svc": child})
    p = _plugin(WindowsServiceImagePath, tmp_path)
    _setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1
    assert "svc.exe" in findings[0].value


def test_windows_service_dll(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1543.windows_services import WindowsServiceDll

    params_node = make_node(name="Parameters", values={"ServiceDll": "C:\\evil.dll"})
    svc_node = make_node(name="svchost_svc", children={"Parameters": params_node})
    tree = make_node(children={"svchost_svc": svc_node})
    p = _plugin(WindowsServiceDll, tmp_path)
    _setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1
    assert "evil.dll" in findings[0].value


# -- RID Hijacking --------------------------------------------------------------


def _make_f_value(rid: int) -> bytes:
    data = b"\x00" * 0x30 + struct.pack("<I", rid) + b"\x00" * 20
    return data


def test_rid_hijacking(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1098.rid_hijacking import RidHijacking

    # Subkey is 000003E9 (RID=1001), but F value says RID=500
    child = make_node(name="000003E9", values={"F": _make_f_value(500)})
    tree = make_node(children={"000003E9": child})
    p = _plugin(RidHijacking, tmp_path)
    _setup_hklm(p, tree, hive_path="/fake/SAM")
    findings = p.run()
    assert len(findings) == 1
    assert "mismatch" in findings[0].value.lower()


def test_rid_hijacking_no_mismatch(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1098.rid_hijacking import RidHijacking

    child = make_node(name="000001F4", values={"F": _make_f_value(500)})
    tree = make_node(children={"000001F4": child})
    p = _plugin(RidHijacking, tmp_path)
    _setup_hklm(p, tree, hive_path="/fake/SAM")
    assert p.run() == []


def test_rid_suborner(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1098.rid_hijacking import RidSuborner

    child = make_node(name="000003E9", values={"F": _make_f_value(500)})
    tree = make_node(children={"000003E9": child})
    p = _plugin(RidSuborner, tmp_path)
    _setup_hklm(p, tree, hive_path="/fake/SAM")
    findings = p.run()
    assert len(findings) == 1
    assert "suborner" in findings[0].value.lower()


# -- AMSI Providers ------------------------------------------------------------


def test_amsi_providers(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.amsi_providers import AmsiProviders

    clsid_child = make_node(name="{AAAA-BBBB}")
    tree = make_node(children={"{AAAA-BBBB}": clsid_child})
    p = _plugin(AmsiProviders, tmp_path)
    p.image.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    # AMSI tree first, then InprocServer32 lookup
    inproc_node = make_node(values={"(Default)": "C:\\evil_amsi.dll"})
    p.registry.load_subtree.side_effect = [tree, inproc_node]
    findings = p.run()
    assert len(findings) == 1
    assert "evil_amsi.dll" in findings[0].value


# -- App Paths -----------------------------------------------------------------


def test_app_paths(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.app_paths import AppPaths

    child = make_node(name="evil.exe", values={"(Default)": "C:\\malware\\evil.exe"})
    tree = make_node(children={"evil.exe": child})
    p = _plugin(AppPaths, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "evil.exe" in findings[0].value


# -- Telemetry Controller ------------------------------------------------------


def test_telemetry_controller(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.telemetry_controller import (
        TelemetryController,
    )

    child = make_node(name="EvilCtrl", values={"Command": "C:\\evil.exe"})
    tree = make_node(children={"EvilCtrl": child})
    p = _plugin(TelemetryController, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "evil.exe" in findings[0].value


# -- Power Automate Desktop ----------------------------------------------------


def test_power_automate(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.power_automate import PowerAutomate

    profiles = [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]
    p = _plugin(PowerAutomate, tmp_path, user_profiles=profiles)
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
    assert findings[0].value == "EvilFlow"


# -- Explorer Persistence (Load, BHO, AppKey) ----------------------------------


def test_explorer_bho(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.explorer_persistence import (
        ExplorerBrowserHelperObjects,
    )

    clsid_child = make_node(name="{BHO-CLSID}")
    tree = make_node(children={"{BHO-CLSID}": clsid_child})
    p = _plugin(ExplorerBrowserHelperObjects, tmp_path)
    p.image.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    inproc_node = make_node(values={"(Default)": "C:\\bho.dll"})
    # load_subtree: first call for BHO tree, second for InprocServer32
    p.registry.load_subtree.side_effect = [tree, inproc_node]
    findings = p.run()
    assert len(findings) == 1
    assert "bho.dll" in findings[0].value


def test_explorer_app_key(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.explorer_persistence import (
        ExplorerAppKey,
    )

    child = make_node(name="18", values={"ShellExecute": "C:\\evil.exe"})
    tree = make_node(children={"18": child})
    p = _plugin(ExplorerAppKey, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "evil.exe" in findings[0].value


# -- WER Runtime Exception Helper Modules --------------------------------------


def test_wer_runtime_exception(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.debugger_hijacking import (
        WerRuntimeExceptionHelperModules,
    )

    tree = make_node(values={"C:\\evil\\helper.dll": 0})
    p = _plugin(WerRuntimeExceptionHelperModules, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "helper.dll" in findings[0].value


# -- Office Add-ins ------------------------------------------------------------


def test_office_addins_hklm(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.office_addins import OfficeAddins

    addin_node = make_node(name="EvilAddin", values={"Manifest": "C:\\evil.manifest"})
    word_tree = make_node(children={"EvilAddin": addin_node})
    p = _plugin(OfficeAddins, tmp_path)
    p.image.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    # 5 Office apps: return word_tree for Word, None for the rest
    p.registry.load_subtree.side_effect = [word_tree, None, None, None, None]
    findings = p.run()
    assert len(findings) == 1
    assert "evil.manifest" in findings[0].value


def test_office_ai_hijack(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.office_addins import OfficeAiHijack

    tree = make_node(values={"SomeFeature": "{evil-clsid}"})
    p = _plugin(OfficeAiHijack, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "evil-clsid" in findings[0].value


# -- Office DLL Override -------------------------------------------------------


def test_office_dll_override(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.office_dll_override import OfficeDllOverride

    word_node = make_node(name="Word", values={"WwlibtDll": "C:\\evil.dll"})
    version_node = make_node(name="16.0", children={"Word": word_node})
    tree = make_node(children={"16.0": version_node})
    p = _plugin(OfficeDllOverride, tmp_path)
    _setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "evil.dll" in findings[0].value


# -- Office Templates ----------------------------------------------------------


def test_office_templates(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.office_templates import OfficeTemplates

    profiles = [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]
    p = _plugin(OfficeTemplates, tmp_path, user_profiles=profiles)
    tpl = (
        tmp_path
        / "Users"
        / "user1"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Templates"
        / "Normal.dotm"
    )
    tpl.parent.mkdir(parents=True)
    tpl.write_text("malicious macro")
    findings = p.run()
    assert len(findings) == 1
    assert "Normal.dotm" in findings[0].value


# -- VBA Monitors --------------------------------------------------------------


def test_vba_monitors(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.vba_monitors import VbaMonitors

    inproc_node = make_node(values={"(Default)": "C:\\evil_vba.dll"})
    p = _plugin(VbaMonitors, tmp_path)
    p.image.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.return_value = inproc_node
    findings = p.run()
    assert len(findings) == 1
    assert "evil_vba.dll" in findings[0].value


# -- DotNet Startup Hooks ------------------------------------------------------


def test_dotnet_startup_hooks(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1574.dotnet_startup_hooks import DotNetStartupHooks

    env_node = make_node(values={"DOTNET_STARTUP_HOOKS": "C:\\evil_hook.dll"})
    p = _plugin(DotNetStartupHooks, tmp_path)
    p.image.hive_path.return_value = Path("/fake/SYSTEM")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.return_value = env_node
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil_hook.dll" in f.value for f in findings)


# -- Profiler Env Vars ---------------------------------------------------------


def test_cor_profiler(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1574.profiler_env_vars import CorProfiler

    env_node = make_node(
        values={"COR_PROFILER": "{evil-guid}", "COR_ENABLE_PROFILING": "1"}
    )
    p = _plugin(CorProfiler, tmp_path)
    _setup_hklm(p, env_node, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil-guid" in f.value for f in findings)


# -- DSRM Backdoor -------------------------------------------------------------


def test_dsrm_backdoor(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1547.dsrm_backdoor import DsrmBackdoor

    node = make_node(values={"DsrmAdminLogonBehavior": 2})
    p = _plugin(DsrmBackdoor, tmp_path)
    p.image.hive_path.return_value = Path("/fake/SYSTEM")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    # 3 controlsets checked: ControlSet001, ControlSet002, CurrentControlSet
    p.registry.load_subtree.side_effect = [node, None, None]
    findings = p.run()
    assert len(findings) == 1
    assert findings[0].value == "2"


# -- Accessibility Tools -------------------------------------------------------


def test_accessibility_tools(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.accessibility_tools import AccessibilityTools

    p = _plugin(AccessibilityTools, tmp_path)
    # Create cmd.exe with known content
    cmd_dir = tmp_path / "Windows" / "System32"
    cmd_dir.mkdir(parents=True)
    (cmd_dir / "cmd.exe").write_bytes(b"fake-cmd-content")
    # sethc.exe has the same content as cmd.exe (replaced)
    (cmd_dir / "sethc.exe").write_bytes(b"fake-cmd-content")
    # powershell, pwsh, explorer can be absent or different
    findings = p.run()
    assert len(findings) == 1
    assert "sethc.exe" in findings[0].path


# -- Group Policy Scripts ------------------------------------------------------


def test_gp_scripts(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1037.gp_scripts import GpScripts

    p = _plugin(GpScripts, tmp_path)
    scripts_dir = (
        tmp_path / "Windows" / "System32" / "GroupPolicy" / "Machine" / "Scripts"
    )
    scripts_dir.mkdir(parents=True)
    ini = scripts_dir / "scripts.ini"
    ini.write_text(
        "[Startup]\n0CmdLine=C:\\evil.bat\n0Parameters=-silent\n", encoding="utf-8"
    )
    findings = p.run()
    assert len(findings) == 1
    assert "evil.bat" in findings[0].value


# -- Windows Terminal ----------------------------------------------------------


def test_windows_terminal(tmp_path: Path) -> None:
    import json as _json

    from pyrsistencesniper.plugins.T1546.windows_terminal import WindowsTerminal

    profiles = [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]
    p = _plugin(WindowsTerminal, tmp_path, user_profiles=profiles)
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
    assert "evil" in findings[0].value


# -- PowerShell Profiles -------------------------------------------------------


def test_powershell_profiles(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1546.powershell_profiles import PowerShellProfiles

    p = _plugin(PowerShellProfiles, tmp_path)
    ps_dir = tmp_path / "Windows" / "System32" / "WindowsPowerShell" / "v1.0"
    ps_dir.mkdir(parents=True)
    (ps_dir / "profile.ps1").write_text("evil-code")
    findings = p.run()
    assert len(findings) >= 1
    assert any("profile.ps1" in f.value for f in findings)
