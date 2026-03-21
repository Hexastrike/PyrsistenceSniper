"""Tests for AccessibilityTools SHA-256 hash comparison plugin."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel

if TYPE_CHECKING:
    from pathlib import Path
from pyrsistencesniper.plugins.T1546.accessibility_tools import AccessibilityTools

from .conftest import make_plugin


class TestAccessibilityTools:
    """AccessibilityTools detects replaced accessibility EXEs via SHA-256."""

    def test_happy_path_sethc_replaced_with_cmd(self, tmp_path: Path) -> None:
        """sethc.exe with same hash as cmd.exe should produce a finding."""
        p = make_plugin(AccessibilityTools, tmp_path)
        sys32 = tmp_path / "Windows" / "System32"
        sys32.mkdir(parents=True)
        (sys32 / "cmd.exe").write_bytes(b"fake-cmd-content")
        (sys32 / "sethc.exe").write_bytes(b"fake-cmd-content")  # same hash
        findings = p.run()
        assert len(findings) == 1
        assert "sethc.exe" in findings[0].path
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert "SHA-256" in findings[0].value

    def test_multiple_tools_replaced(self, tmp_path: Path) -> None:
        """Multiple accessibility tools replaced with same attack binary."""
        p = make_plugin(AccessibilityTools, tmp_path)
        sys32 = tmp_path / "Windows" / "System32"
        sys32.mkdir(parents=True)
        payload = b"evil-payload-bytes"
        (sys32 / "powershell.exe").write_bytes(payload)
        (sys32 / "sethc.exe").write_bytes(payload)
        (sys32 / "osk.exe").write_bytes(payload)
        findings = p.run()
        assert len(findings) == 2
        paths = {f.path for f in findings}
        assert any("sethc.exe" in p for p in paths)
        assert any("osk.exe" in p for p in paths)

    def test_hash_does_not_match_attack_binary(self, tmp_path: Path) -> None:
        """Tool exists with different hash than any attack binary -- no finding."""
        p = make_plugin(AccessibilityTools, tmp_path)
        sys32 = tmp_path / "Windows" / "System32"
        sys32.mkdir(parents=True)
        (sys32 / "cmd.exe").write_bytes(b"real-cmd-binary")
        (sys32 / "sethc.exe").write_bytes(b"legitimate-sethc-binary")
        findings = p.run()
        assert findings == []

    def test_zero_length_binary(self, tmp_path: Path) -> None:
        """Zero-length attack binary still produces a valid hash for comparison."""
        p = make_plugin(AccessibilityTools, tmp_path)
        sys32 = tmp_path / "Windows" / "System32"
        sys32.mkdir(parents=True)
        (sys32 / "cmd.exe").write_bytes(b"")
        (sys32 / "sethc.exe").write_bytes(b"")  # both zero-length, same hash
        findings = p.run()
        assert len(findings) == 1
