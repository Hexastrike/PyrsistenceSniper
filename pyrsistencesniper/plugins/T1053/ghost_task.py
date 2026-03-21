"""Detect ghost scheduled tasks -- registry entries with no corresponding XML file."""

from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FilterRule,
    Finding,
)
from pyrsistencesniper.core.registry import RegistryNode
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_TASK_CACHE_TREE = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
_TASK_CACHE_TASKS = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
_MAX_DEPTH = 50


@register_plugin
class GhostTask(PersistencePlugin):
    definition = CheckDefinition(
        id="ghost_task",
        technique="Ghost Scheduled Task",
        mitre_id="T1053.005",
        description=(
            "Ghost tasks have a registry entry in TaskCache\\Tree but no "
            "corresponding XML file under System32\\Tasks. This technique "
            "hides scheduled tasks from the Task Scheduler UI and "
            "schtasks.exe, making them invisible to standard enumeration."
        ),
        references=("https://attack.mitre.org/techniques/T1053/005/",),
        allow=(
            FilterRule(
                reason="Standard Windows task",
                path_matches=r"Microsoft\\(Windows|OneCore)\\",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self.hive_ops.load_subtree("SOFTWARE", _TASK_CACHE_TREE)
        if tree is None:
            return findings

        tasks_tree = self.hive_ops.load_subtree("SOFTWARE", _TASK_CACHE_TASKS)
        tasks_root = self.filesystem.image_root / "Windows" / "System32" / "Tasks"
        if not tasks_root.is_dir():
            return findings
        self._walk(tree, tasks_tree, _TASK_CACHE_TREE, "", tasks_root, findings)
        return findings

    def _walk(
        self,
        node: RegistryNode,
        tasks_tree: RegistryNode | None,
        registry_path: str,
        task_prefix: str,
        tasks_root: Path,
        findings: list[Finding],
        depth: int = 0,
    ) -> None:
        """Walk TaskCache\\Tree and flag orphaned tasks."""
        if depth >= _MAX_DEPTH:
            return

        for subkey_name, child in node.children():
            full_reg = f"{registry_path}\\{subkey_name}"
            full_task = f"{task_prefix}\\{subkey_name}" if task_prefix else subkey_name

            task_id = child.get("Id")
            if task_id is not None:
                task_id_str = str(task_id)
                disk_name = self._resolve_task_path(tasks_tree, task_id_str, full_task)
                task_file = tasks_root / disk_name
                if not task_file.is_file():
                    findings.append(
                        self._make_finding(
                            path=f"HKLM\\SOFTWARE\\{full_reg}",
                            value=task_id_str,
                            access=AccessLevel.SYSTEM,
                        )
                    )

            self._walk(
                child,
                tasks_tree,
                full_reg,
                full_task,
                tasks_root,
                findings,
                depth + 1,
            )

    @staticmethod
    def _resolve_task_path(
        tasks_tree: RegistryNode | None,
        task_id: str,
        fallback: str,
    ) -> str:
        """Resolve a task GUID to its on-disk path."""
        if tasks_tree is None:
            return fallback
        guid_node = tasks_tree.child(task_id)
        if guid_node is None:
            return fallback
        path_value = guid_node.get("Path")
        if path_value and isinstance(path_value, str):
            return path_value.lstrip("\\")
        return fallback
