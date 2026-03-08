from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.models.finding import AccessLevel

from .conftest import make_node, make_plugin, setup_hklm


def test_service_failure_command(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1543.service_failure_actions import (
        ServiceFailureCommand,
    )

    child = make_node(name="EvilSvc", values={"FailureCommand": "C:\\evil.exe"})
    tree = make_node(children={"EvilSvc": child})
    p = make_plugin(ServiceFailureCommand, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.exe" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
    assert "T1543" in f.mitre_id


def test_windows_service_image_path(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1543.windows_services import WindowsServiceImagePath

    child = make_node(name="Svc", values={"ImagePath": "C:\\svc.exe"})
    tree = make_node(children={"Svc": child})
    p = make_plugin(WindowsServiceImagePath, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "svc.exe" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_windows_service_dll(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1543.windows_services import WindowsServiceDll

    params_node = make_node(name="Parameters", values={"ServiceDll": "C:\\evil.dll"})
    svc_node = make_node(name="svchost_svc", children={"Parameters": params_node})
    tree = make_node(children={"svchost_svc": svc_node})
    p = make_plugin(WindowsServiceDll, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.dll" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
