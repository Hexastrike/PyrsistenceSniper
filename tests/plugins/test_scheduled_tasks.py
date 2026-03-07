from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.plugins.T1053.scheduled_tasks import ScheduledTaskFiles

from .conftest import make_deps


def _make_plugin(tmp_path: Path) -> ScheduledTaskFiles:
    image, registry, filesystem, profile = make_deps(tmp_path)
    return ScheduledTaskFiles(
        registry=registry, filesystem=filesystem, image=image, profile=profile
    )


def test_no_tasks_dir(tmp_path: Path) -> None:
    plugin = _make_plugin(tmp_path)
    assert plugin.run() == []


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
