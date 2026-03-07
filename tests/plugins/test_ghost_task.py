from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1053.ghost_task import GhostTask

from .conftest import make_deps, make_node


def _make_plugin(tmp_path: Path) -> GhostTask:
    image, registry, filesystem, profile = make_deps(tmp_path)
    return GhostTask(
        registry=registry, filesystem=filesystem, image=image, profile=profile
    )


def test_no_tree_key(tmp_path: Path) -> None:
    plugin = _make_plugin(tmp_path)
    plugin.registry.load_subtree.return_value = None  # type: ignore[union-attr]
    plugin.image.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]

    assert plugin.run() == []


def test_ghost_task_detected(tmp_path: Path) -> None:
    tasks_dir = tmp_path / "Windows" / "System32" / "Tasks"
    tasks_dir.mkdir(parents=True)

    task_child = make_node(name="EvilTask", values={"Id": "{GUID-123}"})
    tree_node = make_node(name="Tree", children={"EvilTask": task_child})

    plugin = _make_plugin(tmp_path)
    plugin.image.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
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
    plugin.image.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.side_effect = [tree_node, tasks_tree]  # type: ignore[union-attr]

    assert plugin.run() == []


def test_no_tasks_dir_returns_empty(tmp_path: Path) -> None:
    tree_node = make_node(
        name="Tree",
        children={"Task1": make_node(name="Task1", values={"Id": "{G}"})},
    )

    plugin = _make_plugin(tmp_path)
    plugin.image.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.side_effect = [tree_node, None]  # type: ignore[union-attr]

    assert plugin.run() == []
