from __future__ import annotations

import json
from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1546.windows_terminal import WindowsTerminal

from .conftest import make_plugin


def _profiles() -> list[UserProfile]:
    return [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]


def _settings_dir(tmp_path: Path, username: str = "user1") -> Path:
    d = (
        tmp_path
        / "Users"
        / username
        / "AppData"
        / "Local"
        / "Packages"
        / "Microsoft.WindowsTerminal_8wekyb3d8bbwe"
        / "LocalState"
    )
    d.mkdir(parents=True)
    return d


def test_suspicious_commandline(tmp_path: Path) -> None:
    """Non-default command line -- produces USER finding."""
    p = make_plugin(WindowsTerminal, tmp_path, user_profiles=_profiles())
    sd = _settings_dir(tmp_path)
    data = {"profiles": {"list": [{"commandline": "C:\\evil\\shell.exe"}]}}
    (sd / "settings.json").write_text(json.dumps(data), encoding="utf-8")
    findings = p.run()
    assert len(findings) == 1
    assert "evil" in findings[0].value
    assert findings[0].access_gained == AccessLevel.USER


def test_default_commandline_filtered(tmp_path: Path) -> None:
    """Default cmd.exe should not produce finding (include_defaults=False)."""
    p = make_plugin(WindowsTerminal, tmp_path, user_profiles=_profiles())
    sd = _settings_dir(tmp_path)
    data = {"profiles": {"list": [{"commandline": "cmd.exe"}]}}
    (sd / "settings.json").write_text(json.dumps(data), encoding="utf-8")
    findings = p.run()
    assert len(findings) == 0


def test_malformed_json(tmp_path: Path) -> None:
    """Malformed JSON -- should not crash, no findings."""
    p = make_plugin(WindowsTerminal, tmp_path, user_profiles=_profiles())
    sd = _settings_dir(tmp_path)
    (sd / "settings.json").write_text("{broken json!!!", encoding="utf-8")
    findings = p.run()
    assert findings == []


def test_profile_no_commandline(tmp_path: Path) -> None:
    """Profile entry without commandline -- no findings."""
    p = make_plugin(WindowsTerminal, tmp_path, user_profiles=_profiles())
    sd = _settings_dir(tmp_path)
    data = {"profiles": {"list": [{"name": "Default"}]}}
    (sd / "settings.json").write_text(json.dumps(data), encoding="utf-8")
    assert p.run() == []
