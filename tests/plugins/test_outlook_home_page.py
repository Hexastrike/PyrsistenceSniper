from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1137.outlook_home_page import OutlookHomePage

from .conftest import make_node, make_plugin

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    user = UserProfile(
        username="victim",
        profile_path=tmp_path / "Users" / "victim",
        ntuser_path=tmp_path / "ntuser.dat",
    )
    p = make_plugin(OutlookHomePage, tmp_path, user_profiles=[user])

    hive_mock = MagicMock()
    p.registry.open_hive.return_value = hive_mock

    webview_node = make_node(values={"URL": "http://evil.example.com/payload.html"})
    p.registry.load_subtree.return_value = webview_node

    findings = p.run()
    assert len(findings) >= 1
    assert any("evil.example.com" in f.value for f in findings)
    assert all(f.access_gained == AccessLevel.USER for f in findings)


def test_no_users_returns_empty(tmp_path: Path) -> None:
    p = make_plugin(OutlookHomePage, tmp_path)
    assert p.run() == []


def test_no_url_value_skipped(tmp_path: Path) -> None:
    user = UserProfile(
        username="victim",
        profile_path=tmp_path / "Users" / "victim",
        ntuser_path=tmp_path / "ntuser.dat",
    )
    p = make_plugin(OutlookHomePage, tmp_path, user_profiles=[user])

    hive_mock = MagicMock()
    p.registry.open_hive.return_value = hive_mock

    node = make_node(values={"OtherVal": "data"})
    p.registry.load_subtree.return_value = node

    assert p.run() == []
