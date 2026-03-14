from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1543.service_failure_actions import (
    ServiceFailureCommand,
)

if TYPE_CHECKING:
    from pathlib import Path

from .conftest import make_node, make_plugin, setup_hklm


def test_service_failure_command_happy_path(tmp_path: Path) -> None:
    """Service with FailureCommand produces a finding with correct fields."""
    child = make_node(name="EvilSvc", values={"FailureCommand": "C:\\evil.exe"})
    tree = make_node(children={"EvilSvc": child})
    plugin = make_plugin(ServiceFailureCommand, tmp_path)
    setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")

    findings = plugin.run()
    assert len(findings) == 1
    finding = findings[0]
    assert "evil.exe" in finding.value
    assert finding.access_gained == AccessLevel.SYSTEM
    assert "T1543" in finding.mitre_id
    assert "FailureCommand" in finding.path


def test_services_without_failure_command(tmp_path: Path) -> None:
    """Services that lack FailureCommand produce no findings."""
    child = make_node(name="NormalSvc", values={"ImagePath": "C:\\svc.exe"})
    tree = make_node(children={"NormalSvc": child})
    plugin = make_plugin(ServiceFailureCommand, tmp_path)
    setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")

    assert plugin.run() == []
