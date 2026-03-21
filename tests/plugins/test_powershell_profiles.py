from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1546.powershell_profiles import PowerShellProfiles

from .conftest import make_plugin


def test_system_profile_found(tmp_path: Path) -> None:
    """System-wide profile.ps1 exists -- produces SYSTEM finding."""
    p = make_plugin(PowerShellProfiles, tmp_path)
    ps_dir = tmp_path / "Windows" / "System32" / "WindowsPowerShell" / "v1.0"
    ps_dir.mkdir(parents=True)
    (ps_dir / "profile.ps1").write_text("evil-code")
    findings = p.run()
    assert len(findings) >= 1
    assert any("profile.ps1" in f.value for f in findings)
    assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)


def test_user_profile_found(tmp_path: Path) -> None:
    """Per-user profile exists -- produces USER finding."""
    profiles = [
        UserProfile(
            username="victim",
            profile_path=Path("/Users/victim"),
            ntuser_path=Path("/Users/victim/NTUSER.DAT"),
        ),
    ]
    p = make_plugin(PowerShellProfiles, tmp_path, user_profiles=profiles)
    ps_dir = tmp_path / "Users" / "victim" / "Documents" / "WindowsPowerShell"
    ps_dir.mkdir(parents=True)
    (ps_dir / "profile.ps1").write_text("evil-code")
    findings = p.run()
    assert len(findings) >= 1
    assert any(f.access_gained == AccessLevel.USER for f in findings)


def test_multiple_system_profiles(tmp_path: Path) -> None:
    """Multiple system profile files -- multiple findings."""
    p = make_plugin(PowerShellProfiles, tmp_path)
    ps32 = tmp_path / "Windows" / "System32" / "WindowsPowerShell" / "v1.0"
    ps32.mkdir(parents=True)
    (ps32 / "profile.ps1").write_text("x")
    (ps32 / "Microsoft.PowerShell_profile.ps1").write_text("y")
    findings = p.run()
    assert len(findings) == 2
    assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)
