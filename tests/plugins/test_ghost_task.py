from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1053.ghost_task import GhostTask

from .conftest import make_deps, make_node


def _make_plugin(tmp_path: Path) -> GhostTask:
    context, registry, _filesystem, _profile = make_deps(tmp_path)
    context.registry = registry
    return GhostTask(context=context)


def test_ghost_task_detected(tmp_path: Path) -> None:
    tasks_dir = tmp_path / "Windows" / "System32" / "Tasks"
    tasks_dir.mkdir(parents=True)

    task_child = make_node(name="EvilTask", values={"Id": "{GUID-123}"})
    tree_node = make_node(name="Tree", children={"EvilTask": task_child})

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.side_effect = [tree_node, None]  # type: ignore[union-attr]

    findings = plugin.run()
    assert len(findings) == 1
    assert "{GUID-123}" in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_task_with_xml_not_flagged(tmp_path: Path) -> None:
    tasks_dir = tmp_path / "Windows" / "System32" / "Tasks"
    tasks_dir.mkdir(parents=True)
    (tasks_dir / "LegitTask").write_text("<Task/>")

    task_child = make_node(name="LegitTask", values={"Id": "{GUID-OK}"})
    tree_node = make_node(name="Tree", children={"LegitTask": task_child})

    tasks_guid_node = make_node(name="{GUID-OK}", values={"Path": "\\LegitTask"})
    tasks_tree = make_node(name="Tasks", children={"{GUID-OK}": tasks_guid_node})

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.side_effect = [tree_node, tasks_tree]  # type: ignore[union-attr]

    assert plugin.run() == []


def test_multiple_ghost_tasks(tmp_path: Path) -> None:
    """Two registry entries with no corresponding XML files produce two findings."""
    tasks_dir = tmp_path / "Windows" / "System32" / "Tasks"
    tasks_dir.mkdir(parents=True)

    child_a = make_node(name="TaskA", values={"Id": "{GUID-A}"})
    child_b = make_node(name="TaskB", values={"Id": "{GUID-B}"})
    tree_node = make_node(name="Tree", children={"TaskA": child_a, "TaskB": child_b})

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.side_effect = [tree_node, None]  # type: ignore[union-attr]

    findings = plugin.run()
    assert len(findings) == 2
    found_values = {f.value for f in findings}
    assert "{GUID-A}" in found_values
    assert "{GUID-B}" in found_values
    for finding in findings:
        assert finding.access_gained == AccessLevel.SYSTEM
        assert finding.mitre_id == "T1053.005"
        assert finding.path.startswith("HKLM\\SOFTWARE\\")


def test_xml_exists_not_flagged(tmp_path: Path) -> None:
    """When the XML file exists on disk, the task is NOT a ghost task."""
    tasks_dir = tmp_path / "Windows" / "System32" / "Tasks"
    tasks_dir.mkdir(parents=True)
    (tasks_dir / "RealTask").write_text("<Task/>")

    task_child = make_node(name="RealTask", values={"Id": "{GUID-REAL}"})
    tree_node = make_node(name="Tree", children={"RealTask": task_child})

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    # No TaskCache\Tasks tree available, so fallback path = task name
    plugin.registry.load_subtree.side_effect = [tree_node, None]  # type: ignore[union-attr]

    assert plugin.run() == []
