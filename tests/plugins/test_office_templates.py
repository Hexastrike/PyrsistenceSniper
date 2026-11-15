"""Tests for the OfficeTemplates filesystem scan (T1137.001)."""

from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.core.registry import artifact_failures
from pyrsistencesniper.core.resolver import ResolutionPipeline
from pyrsistencesniper.plugins.T1137.office_templates import OfficeTemplates

from .conftest import make_plugin, setup_filesystem

_WORD_STARTUP = r"AppData\Roaming\Microsoft\Word\STARTUP"
_EXCEL_XLSTART = r"AppData\Roaming\Microsoft\Excel\XLSTART"
_TEMPLATES = r"AppData\Roaming\Microsoft\Templates"


def _make_user(tmp_path: Path, username: str = "user1") -> UserProfile:
    """Return a profile whose folders live under the image root."""
    return UserProfile(
        username=username,
        profile_path=Path(f"/Users/{username}"),
        ntuser_path=Path(f"/Users/{username}/NTUSER.DAT"),
    )


def test_normal_dotm_produces_finding(tmp_path: Path) -> None:
    """Word loads Normal.dotm on every launch, in the signed-in user context."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path)]
    )
    setup_filesystem(
        plugin,
        {rf"Users\user1\{_TEMPLATES}\Normal.dotm": "malicious macro"},
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert "Normal.dotm" in findings[0].value
    assert findings[0].access_gained == AccessLevel.USER


def test_template_dir_exists_but_empty_returns_empty(tmp_path: Path) -> None:
    """A Templates directory without Normal.dotm loads no macro at startup."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path)]
    )
    (tmp_path / "Users" / "user1" / _TEMPLATES).mkdir(parents=True)

    assert plugin.run() == []


def test_both_templates_produce_two_findings(tmp_path: Path) -> None:
    """Word and Excel each auto-load their own default, so both are reported."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path)]
    )
    setup_filesystem(
        plugin,
        {
            rf"Users\user1\{_TEMPLATES}\Normal.dotm": "macro1",
            rf"Users\user1\{_EXCEL_XLSTART}\PERSONAL.XLSB": "macro2",
        },
    )

    assert len(plugin.run()) == 2


def test_word_startup_folder_is_enumerated(tmp_path: Path) -> None:
    """Word loads every file in STARTUP, so the folder is listed, not name-matched."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path)]
    )
    setup_filesystem(
        plugin,
        {
            rf"Users\user1\{_WORD_STARTUP}\OfficeHelper.dotm": "AutoExec macro",
            rf"Users\user1\{_WORD_STARTUP}\legacy.wll": b"MZ",
        },
    )

    findings = plugin.run()

    assert sorted(finding.path for finding in findings) == [
        rf"Users\user1\{_WORD_STARTUP}\OfficeHelper.dotm",
        rf"Users\user1\{_WORD_STARTUP}\legacy.wll",
    ]
    assert all(finding.access_gained == AccessLevel.USER for finding in findings)


def test_xlstart_folder_is_enumerated_beyond_personal_xlsb(tmp_path: Path) -> None:
    """Excel auto-opens every file in XLSTART, not only the PERSONAL.XLSB name."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path)]
    )
    setup_filesystem(
        plugin,
        {rf"Users\user1\{_EXCEL_XLSTART}\update.xlam": "add-in payload"},
    )

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        rf"Users\user1\{_EXCEL_XLSTART}\update.xlam"
    ]


def test_machine_wide_office_startup_grants_system(tmp_path: Path) -> None:
    """The Office install's own STARTUP and XLSTART folders load for every user."""
    plugin = make_plugin(OfficeTemplates, tmp_path)
    setup_filesystem(
        plugin,
        {
            r"Program Files\Microsoft Office\root\Office16\STARTUP\PDFMaker.dotm": "x",
            r"Program Files (x86)\Microsoft Office\Office15\XLSTART\vendor.xlam": "y",
        },
    )

    findings = plugin.run()

    assert sorted(finding.path for finding in findings) == [
        r"Program Files (x86)\Microsoft Office\Office15\XLSTART\vendor.xlam",
        r"Program Files\Microsoft Office\root\Office16\STARTUP\PDFMaker.dotm",
    ]
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)


def test_ordinary_user_templates_stay_quiet(tmp_path: Path) -> None:
    """Templates holds documents Office never auto-loads; only the defaults count."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path)]
    )
    setup_filesystem(
        plugin,
        {
            rf"Users\user1\{_TEMPLATES}\MyLetterhead.dotx": "an ordinary template",
            rf"Users\user1\{_TEMPLATES}\Invoice.dotx": "another one",
            rf"Users\user1\{_TEMPLATES}\LiveContent\report.dotx": "nested",
        },
    )

    assert plugin.run() == []


def test_empty_global_template_folders_stay_quiet(tmp_path: Path) -> None:
    """A stock Office install leaves STARTUP and XLSTART empty and reports nothing."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path)]
    )
    setup_filesystem(
        plugin,
        {
            rf"Users\user1\{_WORD_STARTUP}\desktop.ini": "[.ShellClassInfo]",
            rf"Users\user1\{_EXCEL_XLSTART}\desktop.ini": "[.ShellClassInfo]",
        },
    )

    assert plugin.run() == []


def test_overfilled_folder_is_capped_and_recorded(tmp_path: Path) -> None:
    """A folder stuffed to bury one entry is bounded, and the report says so."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path)]
    )
    setup_filesystem(
        plugin,
        {
            rf"Users\user1\{_WORD_STARTUP}\filler{index:04d}.dotm": "x"
            for index in range(200)
        },
    )

    findings = plugin.run()

    assert len(findings) == 128
    assert len(artifact_failures()) == 1
    assert "office_templates artifact" in artifact_failures()[0].label


def test_template_under_a_profile_name_with_a_space_resolves(tmp_path: Path) -> None:
    """resolve_target makes the template itself the artifact the pipeline hashes."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path, "John Doe")]
    )
    setup_filesystem(
        plugin, {rf"Users\John Doe\{_TEMPLATES}\Normal.dotm": "AutoOpen macro"}
    )

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].resolve_target == findings[0].path

    resolved = ResolutionPipeline(plugin.filesystem).resolve(findings[0])
    assert resolved.exists is True
    assert resolved.sha256


def test_startup_file_under_a_profile_name_with_a_space_resolves(
    tmp_path: Path,
) -> None:
    """An enumerated STARTUP add-in is hashed too, space in the profile name or not."""
    plugin = make_plugin(
        OfficeTemplates, tmp_path, user_profiles=[_make_user(tmp_path, "John Doe")]
    )
    setup_filesystem(
        plugin, {rf"Users\John Doe\{_WORD_STARTUP}\OfficeHelper.dotm": "AutoExec macro"}
    )

    findings = plugin.run()
    assert len(findings) == 1

    resolved = ResolutionPipeline(plugin.filesystem).resolve(findings[0])
    assert resolved.exists is True
    assert resolved.sha256
