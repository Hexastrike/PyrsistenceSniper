"""Tests for OfficeDllOverride plugin."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel

if TYPE_CHECKING:
    from pathlib import Path
from pyrsistencesniper.plugins.T1137.office_dll_override import OfficeDllOverride

from .conftest import make_node, make_plugin, setup_hklm


def test_word_override_dll_produces_finding(tmp_path: Path) -> None:
    """Version/app nested tree with WwlibtDll override produces finding."""
    word_node = make_node(name="Word", values={"WwlibtDll": "C:\\evil.dll"})
    version_node = make_node(name="16.0", children={"Word": word_node})
    tree = make_node(children={"16.0": version_node})

    plugin = make_plugin(OfficeDllOverride, tmp_path)
    setup_hklm(plugin, tree)

    findings = plugin.run()

    assert len(findings) == 1
    f = findings[0]
    assert "evil.dll" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
    assert "16.0" in f.path
    assert "Word" in f.path


def test_version_key_no_app_subkeys_returns_empty(tmp_path: Path) -> None:
    """Version key exists but has no Word or PowerPoint children."""
    version_node = make_node(name="16.0", children={})
    tree = make_node(children={"16.0": version_node})

    plugin = make_plugin(OfficeDllOverride, tmp_path)
    setup_hklm(plugin, tree)

    findings = plugin.run()
    assert findings == []


def test_powerpoint_override_dll_produces_finding(tmp_path: Path) -> None:
    """PPCoreTDLL override under PowerPoint produces finding."""
    ppt_node = make_node(name="PowerPoint", values={"PPCoreTDLL": "C:\\evil_ppt.dll"})
    version_node = make_node(name="15.0", children={"PowerPoint": ppt_node})
    tree = make_node(children={"15.0": version_node})

    plugin = make_plugin(OfficeDllOverride, tmp_path)
    setup_hklm(plugin, tree)

    findings = plugin.run()

    assert len(findings) == 1
    assert "evil_ppt.dll" in findings[0].value
