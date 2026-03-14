from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1546.screensaver import Screensaver

from .conftest import make_node, make_plugin


def _profiles() -> list[UserProfile]:
    return [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]


def test_screensaver_found(tmp_path: Path) -> None:
    """User hive with SCRNSAVE.EXE -- produces USER finding."""
    p = make_plugin(Screensaver, tmp_path, user_profiles=_profiles())
    ntuser = MagicMock()
    p.registry.open_hive.return_value = ntuser
    node = make_node(values={"SCRNSAVE.EXE": "C:\\evil.scr"})
    p.registry.load_subtree.return_value = node
    findings = p.run()
    assert len(findings) == 1
    assert "evil.scr" in findings[0].value
    assert findings[0].access_gained == AccessLevel.USER


def test_screensaver_empty_value(tmp_path: Path) -> None:
    """SCRNSAVE.EXE is empty string -- no findings."""
    p = make_plugin(Screensaver, tmp_path, user_profiles=_profiles())
    ntuser = MagicMock()
    p.registry.open_hive.return_value = ntuser
    node = make_node(values={"SCRNSAVE.EXE": "  "})
    p.registry.load_subtree.return_value = node
    assert p.run() == []
