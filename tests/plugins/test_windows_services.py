from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1543.windows_services import (
    WindowsServiceDll,
    WindowsServiceImagePath,
)

if TYPE_CHECKING:
    from pathlib import Path

from .conftest import make_node, make_plugin, setup_hklm


class TestWindowsServiceImagePath:
    """Tests for the WindowsServiceImagePath plugin."""

    def test_happy_path(self, tmp_path: Path) -> None:
        """Service child with ImagePath produces a finding."""
        child = make_node(name="Svc", values={"ImagePath": "C:\\svc.exe"})
        tree = make_node(children={"Svc": child})
        plugin = make_plugin(WindowsServiceImagePath, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")

        findings = plugin.run()
        assert len(findings) == 1
        finding = findings[0]
        assert "svc.exe" in finding.value
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "T1543" in finding.mitre_id
        assert "ImagePath" in finding.path

    def test_service_without_image_path(self, tmp_path: Path) -> None:
        """Service child without ImagePath value returns no findings."""
        child = make_node(name="Svc", values={"Description": "Some service"})
        tree = make_node(children={"Svc": child})
        plugin = make_plugin(WindowsServiceImagePath, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")

        assert plugin.run() == []


class TestWindowsServiceDll:
    """Tests for the WindowsServiceDll plugin (nested Parameters child lookup)."""

    def test_happy_path_nested_parameters(self, tmp_path: Path) -> None:
        """Service with Parameters/ServiceDll produces a finding."""
        params_node = make_node(
            name="Parameters", values={"ServiceDll": "C:\\evil.dll"}
        )
        svc_node = make_node(name="svchost_svc", children={"Parameters": params_node})
        tree = make_node(children={"svchost_svc": svc_node})
        plugin = make_plugin(WindowsServiceDll, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")

        findings = plugin.run()
        assert len(findings) == 1
        finding = findings[0]
        assert "evil.dll" in finding.value
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "T1543" in finding.mitre_id
        assert "Parameters\\ServiceDll" in finding.path

    def test_service_without_parameters_subkey(self, tmp_path: Path) -> None:
        """Service child without a Parameters subkey returns no findings."""
        svc_node = make_node(name="PlainSvc", values={"ImagePath": "C:\\svc.exe"})
        tree = make_node(children={"PlainSvc": svc_node})
        plugin = make_plugin(WindowsServiceDll, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")

        assert plugin.run() == []

    def test_parameters_without_service_dll(self, tmp_path: Path) -> None:
        """Parameters subkey exists but lacks ServiceDll -- no findings."""
        params_node = make_node(name="Parameters", values={"SomeOtherValue": "data"})
        svc_node = make_node(name="SvcWithParams", children={"Parameters": params_node})
        tree = make_node(children={"SvcWithParams": svc_node})
        plugin = make_plugin(WindowsServiceDll, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")

        assert plugin.run() == []

    def test_multiple_services_mixed(self, tmp_path: Path) -> None:
        """Only services with Parameters/ServiceDll produce findings."""
        params_a = make_node(name="Parameters", values={"ServiceDll": "C:\\a.dll"})
        svc_a = make_node(name="SvcA", children={"Parameters": params_a})
        svc_b = make_node(name="SvcB", values={"ImagePath": "C:\\b.exe"})
        tree = make_node(children={"SvcA": svc_a, "SvcB": svc_b})
        plugin = make_plugin(WindowsServiceDll, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")

        findings = plugin.run()
        assert len(findings) == 1
        assert "a.dll" in findings[0].value
