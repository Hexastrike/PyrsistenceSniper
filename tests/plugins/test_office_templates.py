"""Tests for OfficeTemplates filesystem-scanning plugin."""

from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1137.office_templates import OfficeTemplates

from .conftest import make_plugin


def _make_user(tmp_path: Path, username: str = "user1") -> UserProfile:
    """Create a UserProfile pointing into tmp_path."""
    return UserProfile(
        username=username,
        profile_path=Path(f"/Users/{username}"),
        ntuser_path=Path(f"/Users/{username}/NTUSER.DAT"),
    )


def test_normal_dotm_produces_finding(tmp_path: Path) -> None:
    """Normal.dotm present at expected path produces USER finding."""
    user = _make_user(tmp_path)
    plugin = make_plugin(OfficeTemplates, tmp_path, user_profiles=[user])

    tpl = (
        tmp_path
        / "Users"
        / "user1"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Templates"
        / "Normal.dotm"
    )
    tpl.parent.mkdir(parents=True)
    tpl.write_text("malicious macro")

    findings = plugin.run()

    assert len(findings) == 1
    f = findings[0]
    assert "Normal.dotm" in f.value
    assert f.access_gained == AccessLevel.USER


def test_template_dir_exists_but_empty_returns_empty(tmp_path: Path) -> None:
    """Template directory exists but Normal.dotm is absent."""
    user = _make_user(tmp_path)
    plugin = make_plugin(OfficeTemplates, tmp_path, user_profiles=[user])

    tpl_dir = (
        tmp_path / "Users" / "user1" / "AppData" / "Roaming" / "Microsoft" / "Templates"
    )
    tpl_dir.mkdir(parents=True)

    assert plugin.run() == []


def test_both_templates_produce_two_findings(tmp_path: Path) -> None:
    """Both Normal.dotm and PERSONAL.XLSB present produce two findings."""
    user = _make_user(tmp_path)
    plugin = make_plugin(OfficeTemplates, tmp_path, user_profiles=[user])

    dotm = (
        tmp_path
        / "Users"
        / "user1"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Templates"
        / "Normal.dotm"
    )
    xlsb = (
        tmp_path
        / "Users"
        / "user1"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Excel"
        / "XLSTART"
        / "PERSONAL.XLSB"
    )
    dotm.parent.mkdir(parents=True)
    dotm.write_text("macro1")
    xlsb.parent.mkdir(parents=True)
    xlsb.write_text("macro2")

    findings = plugin.run()
    assert len(findings) == 2
