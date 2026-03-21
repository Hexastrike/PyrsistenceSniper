"""Tests for OfficeAddins (HKLM + HKU) and OfficeAiHijack plugins."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1137.office_addins import OfficeAddins, OfficeAiHijack

from .conftest import make_node, make_plugin, setup_hklm


class TestOfficeAddins:
    """Tests for the combined OfficeAddins plugin (HKLM + HKU)."""

    def test_hklm_addin_manifest_produces_finding(self, tmp_path: Path) -> None:
        """HKLM addin entry for Word with Manifest value produces a finding."""
        addin_node = make_node(
            name="EvilAddin", values={"Manifest": "C:\\evil.manifest"}
        )
        word_tree = make_node(children={"EvilAddin": addin_node})
        plugin = make_plugin(OfficeAddins, tmp_path)
        plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        plugin.registry.open_hive.return_value = hive
        # 5 apps x 4 versions = 20 calls; Word/no-version returns tree, rest None
        plugin.registry.load_subtree.side_effect = [word_tree] + [None] * 19

        findings = plugin.run()

        assert len(findings) == 1
        f = findings[0]
        assert "evil.manifest" in f.value
        assert f.access_gained == AccessLevel.SYSTEM
        assert f.mitre_id == "T1137.006"

    def test_hklm_addin_keys_no_values_returns_empty(self, tmp_path: Path) -> None:
        """Addin subkeys exist but contain no Manifest/FileName/Path values."""
        empty_addin = make_node(name="SomeAddin", values={})
        tree = make_node(children={"SomeAddin": empty_addin})
        plugin = make_plugin(OfficeAddins, tmp_path)
        plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
        hive = MagicMock()
        plugin.registry.open_hive.return_value = hive
        # 5 apps x 4 versions = 20 calls; first returns tree, rest None
        plugin.registry.load_subtree.side_effect = [tree] + [None] * 19

        findings = plugin.run()
        assert findings == []

    def test_hku_addin_produces_user_finding(self, tmp_path: Path) -> None:
        """User profile with NTUSER.DAT addin entry produces USER access finding."""
        ntuser = tmp_path / "Users" / "bob" / "NTUSER.DAT"
        ntuser.parent.mkdir(parents=True)
        ntuser.touch()
        user = UserProfile(
            username="bob",
            ntuser_path=ntuser,
            profile_path=ntuser.parent,
        )

        addin_node = make_node(name="UserAddin", values={"FileName": "C:\\addin.dll"})
        user_tree = make_node(children={"UserAddin": addin_node})

        plugin = make_plugin(OfficeAddins, tmp_path, user_profiles=[user])
        # HKLM returns no hive
        plugin.context.hive_path.return_value = None
        # HKU: open_hive returns hive, load_subtree: 5 apps x 4 versions = 20 calls
        hive = MagicMock()
        plugin.registry.open_hive.return_value = hive
        plugin.registry.load_subtree.side_effect = [user_tree] + [None] * 19
        type(plugin.context).user_profiles = PropertyMock(return_value=[user])

        findings = plugin.run()

        assert len(findings) == 1
        f = findings[0]
        assert "addin.dll" in f.value
        assert f.access_gained == AccessLevel.USER


class TestOfficeAiHijack:
    """Tests for the OfficeAiHijack plugin."""

    def test_ai_value_produces_finding(self, tmp_path: Path) -> None:
        tree = make_node(values={"SomeFeature": "{evil-clsid}"})
        plugin = make_plugin(OfficeAiHijack, tmp_path)
        setup_hklm(plugin, tree)

        findings = plugin.run()

        assert len(findings) == 1
        assert "evil-clsid" in findings[0].value
