"""Tests for scheduled task XML parsing and the sc.exe allow rule (T1053)."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import FilterRule, Finding, MatchResult, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import artifact_failures
from pyrsistencesniper.core.windows import _io_path
from pyrsistencesniper.plugins.T1053.scheduled_tasks import ScheduledTaskFiles

from ..conftest import remove_over_length_tree
from .conftest import make_deps, make_node, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_EVIL_CLSID = "{9F1C11AA-4A2E-4D0B-9F5C-1D2E3F4A5B6C}"
_EDP_CLSID = "{61BCD1B9-340C-40EC-9D41-D7F1C0632F05}"
_LONG_SEGMENT = "TaskFolderWithAVeryLongNameThatPushesThePathPastTheWin32Limit"


def _make_plugin(tmp_path: Path) -> ScheduledTaskFiles:
    """Build a ScheduledTaskFiles reading the real tmp_path tree, not a mock hive."""
    context, _registry, _filesystem = make_deps(tmp_path)
    return ScheduledTaskFiles(context=context)


def _task_xml(actions: str) -> str:
    """Wrap action elements in the Task Scheduler document the parser expects."""
    return (
        '<?xml version="1.0"?>'
        f'<Task xmlns="{_TASK_NAMESPACE}">'
        f"<Actions>{actions}</Actions>"
        "</Task>"
    )


def _com_handler(clsid: str) -> str:
    """Render a ComHandler action naming the CLSID the scheduler would activate."""
    return f"<ComHandler><ClassId>{clsid}</ClassId><Data>AA==</Data></ComHandler>"


def _write_task(tmp_path: Path, task_name: str, xml: str) -> Path:
    """Create one task XML file under the image root's Tasks directory."""
    task_file = tmp_path / "Windows" / "System32" / "Tasks" / task_name
    _io_path(task_file.parent).mkdir(parents=True, exist_ok=True)
    _io_path(task_file).write_text(xml, encoding="utf-8")
    return task_file


def test_xml_with_exec_action(tmp_path: Path) -> None:
    """Command and Arguments are joined, since the arguments often carry the tell."""
    _write_task(
        tmp_path,
        "EvilTask",
        _task_xml(
            "<Exec>"
            "<Command>C:\\malware.exe</Command>"
            "<Arguments>--stealth</Arguments>"
            "</Exec>"
        ),
    )

    plugin = _make_plugin(tmp_path)
    findings = plugin.run()
    assert len(findings) == 1
    assert "malware.exe" in findings[0].value
    assert "--stealth" in findings[0].value


def test_invalid_xml_is_reported_as_lost_coverage(tmp_path: Path) -> None:
    """A task file that exists but will not parse is named, not silently dropped."""
    bad_task = _write_task(tmp_path, "BadXml", "not xml at all <<<")

    plugin = _make_plugin(tmp_path)
    assert plugin.run() == []

    (failure,) = artifact_failures()
    assert failure.label == f"scheduled_task_files artifact {bad_task}"
    assert "ParseError" in failure.error


def test_nested_task_directory(tmp_path: Path) -> None:
    """The folder hierarchy becomes the task name the event log records it under."""
    _write_task(
        tmp_path,
        "Microsoft\\Windows\\Defrag",
        _task_xml("<Exec><Command>defrag.exe</Command></Exec>"),
    )

    plugin = _make_plugin(tmp_path)
    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "defrag.exe"
    assert "Microsoft\\Windows\\Defrag" in findings[0].path


def test_task_beyond_the_win32_path_limit_is_parsed(tmp_path: Path) -> None:
    """An over-length task is read, not confirmed present and then silently dropped."""
    tasks_dir = tmp_path / "Windows" / "System32" / "Tasks"
    deep_folder = tasks_dir
    while len(str(deep_folder / "EvilTask")) < 270:
        deep_folder = deep_folder / _LONG_SEGMENT
    task_file = deep_folder / "EvilTask"

    try:
        _write_task(
            tmp_path,
            str(task_file.relative_to(tasks_dir)),
            _task_xml("<Exec><Command>C:\\malware.exe</Command></Exec>"),
        )

        plugin = _make_plugin(tmp_path)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "C:\\malware.exe"
        assert artifact_failures() == ()
    finally:
        remove_over_length_tree(task_file, tasks_dir)


def test_comhandler_action_reports_the_registered_inproc_server(tmp_path: Path) -> None:
    """A ComHandler task is reported by its CLSID's DLL, so the DLL gets hashed."""
    _write_task(tmp_path, "Updater", _task_xml(_com_handler(_EVIL_CLSID)))

    plugin = _make_plugin(tmp_path)
    setup_keys(
        plugin,
        {
            "Classes\\CLSID\\{9F1C11AA-4A2E-4D0B-9F5C-1D2E3F4A5B6C}"
            "\\InprocServer32": make_node(
                values={"(Default)": "C:\\ProgramData\\evil.dll"}
            ),
        },
    )

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "C:\\ProgramData\\evil.dll"
    assert findings[0].path == "Windows\\System32\\Tasks\\Updater"
    assert _EVIL_CLSID in findings[0].description


def test_comhandler_action_falls_back_to_the_local_server(tmp_path: Path) -> None:
    """An out-of-process ComHandler names its LocalServer32 executable."""
    _write_task(tmp_path, "Updater", _task_xml(_com_handler(_EVIL_CLSID)))

    plugin = _make_plugin(tmp_path)
    setup_keys(
        plugin,
        {
            "Classes\\CLSID\\{9F1C11AA-4A2E-4D0B-9F5C-1D2E3F4A5B6C}"
            "\\LocalServer32": make_node(
                values={"(Default)": "C:\\ProgramData\\evil.exe"}
            ),
        },
    )

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "C:\\ProgramData\\evil.exe"


def test_comhandler_without_a_registered_server_is_not_reported(
    tmp_path: Path,
) -> None:
    """A CLSID registering no server has no image to hash, sign, or classify."""
    _write_task(tmp_path, "Updater", _task_xml(_com_handler(_EVIL_CLSID)))

    plugin = _make_plugin(tmp_path)
    setup_keys(plugin, {})

    assert plugin.run() == []


def test_exec_and_comhandler_actions_are_both_reported(tmp_path: Path) -> None:
    """A task mixing action types yields one finding per executable action."""
    _write_task(
        tmp_path,
        "Updater",
        _task_xml(
            "<Exec><Command>C:\\malware.exe</Command></Exec>"
            + _com_handler(_EVIL_CLSID)
        ),
    )

    plugin = _make_plugin(tmp_path)
    setup_keys(
        plugin,
        {
            "Classes\\CLSID\\{9F1C11AA-4A2E-4D0B-9F5C-1D2E3F4A5B6C}"
            "\\InprocServer32": make_node(
                values={"(Default)": "C:\\ProgramData\\evil.dll"}
            ),
        },
    )

    values = [finding.value for finding in plugin.run()]
    assert values == ["C:\\malware.exe", "C:\\ProgramData\\evil.dll"]


def test_benign_os_comhandler_stays_below_the_reporting_floor(tmp_path: Path) -> None:
    """A signed OS ComHandler DLL must not surface at the default severity floor."""
    _write_task(
        tmp_path,
        "Microsoft\\Windows\\EDP\\EDP Auth Task",
        _task_xml(_com_handler(_EDP_CLSID)),
    )

    plugin = _make_plugin(tmp_path)
    setup_keys(
        plugin,
        {
            "Classes\\CLSID\\{61BCD1B9-340C-40EC-9D41-D7F1C0632F05}"
            "\\InprocServer32": make_node(
                values={"(Default)": "%SystemRoot%\\System32\\edptask.dll"}
            ),
        },
    )

    (finding,) = plugin.run()
    resolved = dataclasses.replace(
        finding,
        exists=True,
        signer="Microsoft Windows",
        is_lolbin=False,
        is_builtin=False,
    )
    policy = DetectionProfile.load(None).policy_for("scheduled_task_files")
    assert policy.classify(resolved) < Severity.MEDIUM


def test_attacker_comhandler_dll_reaches_the_reporting_floor(tmp_path: Path) -> None:
    """An unsigned DLL behind a ComHandler CLSID must reach the default floor."""
    _write_task(tmp_path, "Updater", _task_xml(_com_handler(_EVIL_CLSID)))

    plugin = _make_plugin(tmp_path)
    setup_keys(
        plugin,
        {
            "Classes\\CLSID\\{9F1C11AA-4A2E-4D0B-9F5C-1D2E3F4A5B6C}"
            "\\InprocServer32": make_node(
                values={"(Default)": "C:\\ProgramData\\evil.dll"}
            ),
        },
    )

    (finding,) = plugin.run()
    resolved = dataclasses.replace(
        finding,
        exists=True,
        signer="",
        is_lolbin=False,
        is_builtin=False,
    )
    policy = DetectionProfile.load(None).policy_for("scheduled_task_files")
    assert policy.classify(resolved) >= Severity.MEDIUM


def _sc_exe_rule() -> FilterRule:
    """Locate the sc.exe allow rule for scheduled_task_files by content."""
    allow = DetectionProfile.load(None).policy_for("scheduled_task_files").allow
    matched = [rule for rule in allow if r"sc\.exe" in rule.value_matches]
    assert len(matched) == 1
    return matched[0]


class TestScExeFilterRule:
    """Cases for the profile rule that allows a signed sc.exe and nothing else."""

    @pytest.mark.parametrize(
        ("value", "signer", "expected"),
        [
            ("sc.exe start wuauserv", "Microsoft Windows", MatchResult.FULL),
            ("sc.exe start wuauserv", "", MatchResult.PARTIAL),
            (
                "sc.exe config trustedinstaller",
                "Microsoft Windows",
                MatchResult.FULL,
            ),
            ("sc.exe delete svc", "Microsoft Windows", MatchResult.NONE),
        ],
        ids=[
            "start-signed-full",
            "start-unsigned-partial",
            "config-signed-full",
            "delete-none",
        ],
    )
    def test_match_result(self, value: str, signer: str, expected: MatchResult) -> None:
        """Signer decides full versus partial; delete is refused either way."""
        finding = Finding(value=value, signer=signer)
        assert _sc_exe_rule().match_result(finding) == expected
