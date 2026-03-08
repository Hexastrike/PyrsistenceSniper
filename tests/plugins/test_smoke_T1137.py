from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel, UserProfile

from .conftest import make_node, make_plugin, setup_hklm


def test_office_addins_hklm(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.office_addins import OfficeAddins

    addin_node = make_node(name="EvilAddin", values={"Manifest": "C:\\evil.manifest"})
    word_tree = make_node(children={"EvilAddin": addin_node})
    p = make_plugin(OfficeAddins, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.side_effect = [word_tree, None, None, None, None]
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.manifest" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
    assert f.mitre_id == "T1137.006"


def test_office_ai_hijack(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.office_addins import OfficeAiHijack

    tree = make_node(values={"SomeFeature": "{evil-clsid}"})
    p = make_plugin(OfficeAiHijack, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    assert "evil-clsid" in findings[0].value


def test_office_dll_override(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.office_dll_override import OfficeDllOverride

    word_node = make_node(name="Word", values={"WwlibtDll": "C:\\evil.dll"})
    version_node = make_node(name="16.0", children={"Word": word_node})
    tree = make_node(children={"16.0": version_node})
    p = make_plugin(OfficeDllOverride, tmp_path)
    setup_hklm(p, tree)
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.dll" in f.value
    assert f.access_gained == AccessLevel.SYSTEM


def test_office_templates(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.office_templates import OfficeTemplates

    profiles = [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]
    p = make_plugin(OfficeTemplates, tmp_path, user_profiles=profiles)
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
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "Normal.dotm" in f.value
    assert f.access_gained == AccessLevel.USER


def test_vba_monitors(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1137.vba_monitors import VbaMonitors

    inproc_node = make_node(values={"(Default)": "C:\\evil_vba.dll"})
    p = make_plugin(VbaMonitors, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.return_value = inproc_node
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil_vba.dll" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
