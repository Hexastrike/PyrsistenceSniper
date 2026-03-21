"""Tests for AppPaths child iteration plugin."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel

if TYPE_CHECKING:
    from pathlib import Path
from pyrsistencesniper.plugins.T1546.app_paths import AppPaths

from .conftest import make_node, make_plugin, setup_hklm


class TestAppPaths:
    """AppPaths enumerates child keys for (Default) executable paths."""

    def test_happy_path_app_with_default_value(self, tmp_path: Path) -> None:
        """App path child with (Default) value produces a finding."""
        child = make_node(
            name="evil.exe",
            values={"(Default)": "C:\\malware\\evil.exe"},
        )
        tree = make_node(children={"evil.exe": child})
        p = make_plugin(AppPaths, tmp_path)
        setup_hklm(p, tree)

        findings = p.run()
        assert len(findings) == 1
        assert "evil.exe" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_child_without_default_value(self, tmp_path: Path) -> None:
        """Child node with no (Default) value is skipped."""
        child = make_node(name="nodefault.exe", values={"Path": "C:\\somewhere"})
        tree = make_node(children={"nodefault.exe": child})
        p = make_plugin(AppPaths, tmp_path)
        setup_hklm(p, tree)

        assert p.run() == []
