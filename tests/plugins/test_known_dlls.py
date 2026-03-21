from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import Finding, MatchResult
from pyrsistencesniper.plugins.T1574.known_dlls import KnownDlls

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    node = make_node(values={"evil": "evil.dll"})
    p = make_plugin(KnownDlls, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1
    assert "evil.dll" in findings[0].value
    assert "T1574" in findings[0].mitre_id


def test_empty_name_skipped(tmp_path: Path) -> None:
    node = make_node(values={"  ": "blank.dll"})
    p = make_plugin(KnownDlls, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SYSTEM")
    assert p.run() == []


def test_multiple_entries(tmp_path: Path) -> None:
    node = make_node(values={"kernel32": "kernel32.dll", "ntdll": "ntdll.dll"})
    p = make_plugin(KnownDlls, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SYSTEM")
    assert len(p.run()) == 2


def test_no_subtree(tmp_path: Path) -> None:
    p = make_plugin(KnownDlls, tmp_path)
    p.context.hive_path.return_value = None
    assert p.run() == []


class TestKnownDllsFilterRule:
    """Tests for the value_matches + signer FilterRule (allow[0])."""

    rule = KnownDlls.definition.allow[0]

    def test_known_dll_signed_full(self) -> None:
        f = Finding(value="SHELL32.dll", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.FULL

    def test_known_dll_case_insensitive(self) -> None:
        f = Finding(value="kernel32.dll", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.FULL

    def test_known_dll_unsigned_partial(self) -> None:
        f = Finding(value="SHELL32.dll", signer="")
        assert self.rule.match_result(f) == MatchResult.PARTIAL

    def test_unknown_dll_none(self) -> None:
        f = Finding(value="evil.dll", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.NONE
