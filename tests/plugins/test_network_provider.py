from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel, Finding, MatchResult
from pyrsistencesniper.plugins.T1556.network_provider import NetworkProviderDll

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    np_node = make_node(
        name="NetworkProvider",
        values={"ProviderPath": r"C:\evil_np.dll"},
    )
    svc_node = make_node(name="EvilSvc", children={"NetworkProvider": np_node})
    tree = make_node(children={"EvilSvc": svc_node})
    p = make_plugin(NetworkProviderDll, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1
    assert "evil_np.dll" in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_service_without_network_provider(tmp_path: Path) -> None:
    svc_node = make_node(name="PlainSvc", values={"ImagePath": "svc.exe"})
    tree = make_node(children={"PlainSvc": svc_node})
    p = make_plugin(NetworkProviderDll, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    assert p.run() == []


def test_network_provider_without_path(tmp_path: Path) -> None:
    np_node = make_node(name="NetworkProvider", values={"Name": "test"})
    svc_node = make_node(name="SvcNP", children={"NetworkProvider": np_node})
    tree = make_node(children={"SvcNP": svc_node})
    p = make_plugin(NetworkProviderDll, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    assert p.run() == []


def test_no_subtree(tmp_path: Path) -> None:
    p = make_plugin(NetworkProviderDll, tmp_path)
    p.context.hive_path.return_value = None
    assert p.run() == []


class TestNetworkProviderFilterRule:
    """Tests for the updated value_matches pattern (allow[0])."""

    rule = NetworkProviderDll.definition.allow[0]

    def test_drprov_matches(self) -> None:
        f = Finding(value=r"C:\Windows\system32\drprov.dll", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.FULL

    def test_ntlanman_matches(self) -> None:
        f = Finding(
            value=r"C:\Windows\system32\ntlanman.dll",
            signer="Microsoft Windows",
        )
        assert self.rule.match_result(f) == MatchResult.FULL

    def test_evil_dll_none(self) -> None:
        f = Finding(value=r"C:\evil.dll", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.NONE
