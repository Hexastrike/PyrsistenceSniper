"""Tests for ComTreatAs CLSID TreatAs enumeration plugin."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel

if TYPE_CHECKING:
    from pathlib import Path
from pyrsistencesniper.plugins.T1546.com_hijack import ComTreatAs

from .conftest import make_node, make_plugin, setup_hklm


class TestComTreatAs:
    """ComTreatAs enumerates CLSIDs with TreatAs subkeys."""

    def test_happy_path_treatas_subkey(self, tmp_path: Path) -> None:
        """CLSID with TreatAs subkey pointing to hijacked CLSID."""
        treat_as_node = make_node(name="TreatAs", values={"(Default)": "{evil-clsid}"})
        clsid_node = make_node(name="{abc}", children={"TreatAs": treat_as_node})
        tree = make_node(children={"{abc}": clsid_node})
        p = make_plugin(ComTreatAs, tmp_path)
        setup_hklm(p, tree)

        findings = p.run()
        assert len(findings) == 1
        assert "{evil-clsid}" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_clsid_without_treatas(self, tmp_path: Path) -> None:
        """CLSID exists but no TreatAs subkey -- no finding."""
        clsid_node = make_node(name="{normal}")
        tree = make_node(children={"{normal}": clsid_node})
        p = make_plugin(ComTreatAs, tmp_path)
        setup_hklm(p, tree)

        assert p.run() == []

    def test_treatas_with_empty_default(self, tmp_path: Path) -> None:
        """TreatAs subkey with empty (Default) value -- no finding."""
        treat_as_node = make_node(name="TreatAs", values={"(Default)": ""})
        clsid_node = make_node(name="{abc}", children={"TreatAs": treat_as_node})
        tree = make_node(children={"{abc}": clsid_node})
        p = make_plugin(ComTreatAs, tmp_path)
        setup_hklm(p, tree)

        assert p.run() == []
