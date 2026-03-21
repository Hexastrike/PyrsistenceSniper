from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import Finding, MatchResult
from pyrsistencesniper.plugins.T1053.scheduled_tasks import ScheduledTaskFiles

if TYPE_CHECKING:
    from pathlib import Path

from .conftest import make_deps


def _make_plugin(tmp_path: Path) -> ScheduledTaskFiles:
    context, _registry, _filesystem, _profile = make_deps(tmp_path)
    return ScheduledTaskFiles(context=context)


def test_xml_with_exec_action(tmp_path: Path) -> None:
    tasks = tmp_path / "Windows" / "System32" / "Tasks"
    tasks.mkdir(parents=True)
    task_xml = tasks / "EvilTask"
    task_xml.write_text(
        '<?xml version="1.0"?>'
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<Actions><Exec>"
        "<Command>C:\\malware.exe</Command>"
        "<Arguments>--stealth</Arguments>"
        "</Exec></Actions></Task>"
    )

    plugin = _make_plugin(tmp_path)
    findings = plugin.run()
    assert len(findings) == 1
    assert "malware.exe" in findings[0].value
    assert "--stealth" in findings[0].value


def test_invalid_xml_skipped(tmp_path: Path) -> None:
    tasks = tmp_path / "Windows" / "System32" / "Tasks"
    tasks.mkdir(parents=True)
    (tasks / "BadXml").write_text("not xml at all <<<")

    plugin = _make_plugin(tmp_path)
    assert plugin.run() == []


def test_nested_task_directory(tmp_path: Path) -> None:
    tasks = tmp_path / "Windows" / "System32" / "Tasks" / "Microsoft" / "Windows"
    tasks.mkdir(parents=True)
    (tasks / "Defrag").write_text(
        '<?xml version="1.0"?>'
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<Actions><Exec><Command>defrag.exe</Command></Exec></Actions></Task>"
    )

    plugin = _make_plugin(tmp_path)
    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "defrag.exe"
    assert "Microsoft\\Windows\\Defrag" in findings[0].path


class TestScExeFilterRule:
    """Tests for the sc.exe value_matches + signer FilterRule (allow[2])."""

    rule = ScheduledTaskFiles.definition.allow[2]

    def test_sc_start_signed_full(self) -> None:
        f = Finding(value="sc.exe start wuauserv", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.FULL

    def test_sc_start_unsigned_partial(self) -> None:
        f = Finding(value="sc.exe start wuauserv", signer="")
        assert self.rule.match_result(f) == MatchResult.PARTIAL

    def test_sc_config_matches(self) -> None:
        f = Finding(value="sc.exe config trustedinstaller", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.FULL

    def test_sc_delete_none(self) -> None:
        f = Finding(value="sc.exe delete svc", signer="Microsoft Windows")
        assert self.rule.match_result(f) == MatchResult.NONE
