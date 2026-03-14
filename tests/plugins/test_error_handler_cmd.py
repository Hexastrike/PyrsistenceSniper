from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1546.error_handler_cmd import ErrorHandlerCmd

from .conftest import make_plugin

if TYPE_CHECKING:
    from pathlib import Path


def test_error_handler_cmd_present(tmp_path: Path) -> None:
    """File exists in System32 -- produces a finding."""
    p = make_plugin(ErrorHandlerCmd, tmp_path)
    cmd_path = tmp_path / "Windows" / "System32" / "ErrorHandler.cmd"
    cmd_path.parent.mkdir(parents=True)
    cmd_path.write_text("@echo owned")
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "ErrorHandler.cmd" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
