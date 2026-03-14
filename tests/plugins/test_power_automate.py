from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.models.finding import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1546.power_automate import PowerAutomate

from .conftest import make_plugin


def _profiles() -> list[UserProfile]:
    return [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]


def test_power_automate_flow_found(tmp_path: Path) -> None:
    """Flow directory present -- produces a finding."""
    p = make_plugin(PowerAutomate, tmp_path, user_profiles=_profiles())
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
    (flows_dir / "EvilFlow").mkdir(parents=True)
    findings = p.run()
    assert len(findings) == 1
    assert findings[0].value == "EvilFlow"
    assert findings[0].access_gained == AccessLevel.USER
