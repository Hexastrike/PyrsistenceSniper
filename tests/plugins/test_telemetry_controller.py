from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1546.telemetry_controller import TelemetryController

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_telemetry_command_found(tmp_path: Path) -> None:
    """Child with Command value -- produces SYSTEM finding."""
    child = make_node(name="EvilCtrl", values={"Command": "C:\\evil.exe"})
    tree = make_node(children={"EvilCtrl": child})
    p = make_plugin(TelemetryController, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "evil.exe" in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_telemetry_no_command_value(tmp_path: Path) -> None:
    """Child without Command -- no findings."""
    child = make_node(name="SomeCtrl", values={"Other": "val"})
    tree = make_node(children={"SomeCtrl": child})
    p = make_plugin(TelemetryController, tmp_path)
    setup_hklm(p, tree)
    assert p.run() == []
