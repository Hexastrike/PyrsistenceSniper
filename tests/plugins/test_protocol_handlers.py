from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import Finding, MatchResult, UserProfile
from pyrsistencesniper.plugins.T1546.protocol_handlers import (
    ProtocolHandlerHijack,
    SearchProtocolHandler,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


class TestProtocolHandlerHijack:
    def test_no_hive_returns_empty(self, tmp_path: Path) -> None:
        p = make_plugin(ProtocolHandlerHijack, tmp_path)
        p.context.hive_path.return_value = None
        assert p.run() == []

    def test_hklm_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"(Default)": r"C:\evil.exe %1"})
        p = make_plugin(ProtocolHandlerHijack, tmp_path)
        setup_hklm(p, node, hive_path="/fake/SOFTWARE")
        findings = p.run()
        assert len(findings) >= 1
        assert any("evil.exe" in f.value for f in findings)

    def test_hku_happy_path(self, tmp_path: Path) -> None:
        user = UserProfile(
            username="victim",
            profile_path=tmp_path / "Users" / "victim",
            ntuser_path=tmp_path / "ntuser.dat",
        )
        p = make_plugin(ProtocolHandlerHijack, tmp_path, user_profiles=[user])
        hive_mock = MagicMock()
        p.registry.open_hive.return_value = hive_mock

        node = make_node(values={"(Default)": r"C:\evil.exe %1"})
        p.registry.load_subtree.return_value = node

        findings = p.run()
        assert len(findings) >= 1
        assert any("evil.exe" in f.value for f in findings)

    def test_no_value_skipped(self, tmp_path: Path) -> None:
        p = make_plugin(ProtocolHandlerHijack, tmp_path)
        p.context.hive_path.return_value = None
        p.registry.open_hive.return_value = None
        p.registry.load_subtree.return_value = None
        assert p.run() == []


class TestProtocolHandlerMsdtFilterRule:
    """Tests for the msdt value_matches + signer FilterRule (allow[0])."""

    rule = ProtocolHandlerHijack.definition.allow[0]

    def test_msdt_signed_full(self) -> None:
        f = Finding(
            value=r"C:\Windows\system32\msdt.exe -id", signer="Microsoft Windows"
        )
        assert self.rule.match_result(f) == MatchResult.FULL

    def test_msdt_unsigned_partial(self) -> None:
        f = Finding(value=r"C:\Windows\system32\msdt.exe -id", signer="")
        assert self.rule.match_result(f) == MatchResult.PARTIAL

    def test_evil_exe_none(self) -> None:
        f = Finding(value=r"C:\evil.exe %1", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.NONE


class TestSearchProtocolHandler:
    def test_no_hive_returns_empty(self, tmp_path: Path) -> None:
        p = make_plugin(SearchProtocolHandler, tmp_path)
        p.context.hive_path.return_value = None
        assert p.run() == []

    def test_hklm_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"(Default)": r"C:\evil.exe %1"})
        p = make_plugin(SearchProtocolHandler, tmp_path)
        setup_hklm(p, node, hive_path="/fake/SOFTWARE")
        findings = p.run()
        assert len(findings) >= 1
        assert any("evil.exe" in f.value for f in findings)
