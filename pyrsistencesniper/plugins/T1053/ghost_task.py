"""Detect scheduled tasks whose TaskCache registrations disagree with each other."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from pyrsistencesniper.core.filesystem import safe_is_dir, safe_is_file
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    EventLogTime,
    Finding,
    TimeEvidence,
)
from pyrsistencesniper.core.registry import RegistryNode
from pyrsistencesniper.core.windows import is_representable_windows_path
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_TASK_CACHE_TREE = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
_TASK_CACHE_TASKS = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"

_NO_TASK_FILE = "no task XML file under System32\\Tasks"
_NO_SECURITY_DESCRIPTOR = (
    "no SD value on its TaskCache\\Tree key, which hides the task from "
    "schtasks.exe and the Task Scheduler UI while it keeps running"
)
_NO_TASKS_ENTRY = "no TaskCache\\Tasks key for its Id"
_NO_TREE_ENTRY = "no TaskCache\\Tree key registering its GUID"

_TARRASK_REFERENCE = (
    "https://www.microsoft.com/en-us/security/blog/2022/04/12/"
    "tarrask-malware-uses-scheduled-task-defense-evasion/"
)


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    """One TaskCache\\Tree key that registers a task, as read from the hive."""

    registry_path: str
    task_path: str
    task_id: str
    has_security_descriptor: bool


def _has_security_descriptor(node: RegistryNode) -> bool:
    """Report whether a TaskCache\\Tree key still carries a non-empty SD value."""
    security_descriptor = node.get("SD")
    if security_descriptor is None:
        return False
    if isinstance(security_descriptor, (bytes, bytearray, str)):
        return len(security_descriptor) > 0
    return True


def _collect_tree_entries(
    node: RegistryNode,
    registry_path: str,
    task_prefix: str,
    entries: list[_TreeEntry],
) -> None:
    """Recurse through TaskCache\\Tree collecting each key that registers a task."""
    for subkey_name, child in node.children():
        full_reg = f"{registry_path}\\{subkey_name}"
        full_task = f"{task_prefix}\\{subkey_name}" if task_prefix else subkey_name

        task_id = child.get("Id")
        if task_id is not None:
            entries.append(
                _TreeEntry(
                    registry_path=full_reg,
                    task_path=full_task,
                    task_id=str(task_id),
                    has_security_descriptor=_has_security_descriptor(child),
                )
            )

        _collect_tree_entries(child, full_reg, full_task, entries)


def _tree_entries(tree: RegistryNode) -> list[_TreeEntry]:
    """Read every task registration held in a TaskCache\\Tree subtree."""
    entries: list[_TreeEntry] = []
    _collect_tree_entries(tree, _TASK_CACHE_TREE, "", entries)
    return entries


def _describe(task_path: str, anomalies: list[str]) -> str:
    """Render the inconsistencies found for one task as the report's description."""
    return f"Scheduled task \\{task_path} has {'; '.join(anomalies)}."


def _time_evidence(task_path: str) -> tuple[TimeEvidence, ...]:
    """Name the event log records that date a registration of this task."""
    event_key = f"\\{task_path}"
    return (
        EventLogTime(
            channel="Security",
            event_ids=(4698, 4699),
            match_field="TaskName",
            match_value=event_key,
        ),
        EventLogTime(
            channel="Microsoft-Windows-TaskScheduler/Operational",
            event_ids=(106, 140, 141),
            match_field="TaskName",
            match_value=event_key,
        ),
    )


# The name comes from the registry and is attacker controlled: an absolute or
# traversing value resolved against the analyst's own filesystem could make a
# planted task look present, so it is refused and reported as a ghost task.
def _task_file(tasks_root: Path, disk_name: str) -> Path | None:
    """Resolve a task name under the Tasks directory, or None if it escapes it."""
    try:
        relative = PureWindowsPath(disk_name.replace("/", "\\").lstrip("\\"))
        if relative.drive or relative.is_absolute() or ".." in relative.parts:
            return None
        if not is_representable_windows_path(str(relative)):
            return None
        candidate = (tasks_root / Path(*relative.parts)).resolve()
        if not candidate.is_relative_to(tasks_root.resolve()):
            return None
    except (OSError, ValueError):
        return None
    return candidate


def _disk_task_path(guid_node: RegistryNode | None, fallback: str) -> str:
    """Resolve a task's on-disk path from its TaskCache\\Tasks key."""
    if guid_node is None:
        return fallback
    path_value = guid_node.get("Path")
    if path_value and isinstance(path_value, str):
        return path_value.lstrip("\\")
    return fallback


# The ghost_task allow rule in config/default_profile.yaml covering the
# Microsoft\Windows and Microsoft\OneCore task folders is load-bearing: removing
# it once produced 32 false positives on a clean, fully patched Windows 11.
@register_plugin
class GhostTask(PersistencePlugin):
    """Flags TaskCache entries that disagree with the task's other registrations."""

    definition = CheckDefinition(
        id="ghost_task",
        technique="Ghost Scheduled Task",
        mitre_id="T1053.005",
        description=(
            "A scheduled task registers itself three times: a TaskCache\\Tree key, a "
            "TaskCache\\Tasks key and an XML file under System32\\Tasks. A Tree key "
            "with no XML file keeps running while schtasks.exe and the Task Scheduler "
            "UI cannot show what it does, and a Tree or Tasks key missing its "
            "counterpart is the residue of a partially planted or partially deleted "
            "task."
        ),
        references=("https://attack.mitre.org/techniques/T1053/005/",),
    )

    def run(self) -> list[Finding]:
        """Report every TaskCache entry that disagrees with its own other halves."""
        tree = self.context.load_subtree("SOFTWARE", _TASK_CACHE_TREE)
        if tree is None:
            return []

        tasks_root = self.filesystem.resolve("Windows\\System32\\Tasks")
        if not safe_is_dir(tasks_root):
            return []

        tasks_tree = self.context.load_subtree("SOFTWARE", _TASK_CACHE_TASKS)
        tree_entries = _tree_entries(tree)

        findings: list[Finding] = []
        for entry in tree_entries:
            finding = self._tree_finding(entry, tasks_tree, tasks_root)
            if finding is not None:
                findings.append(finding)
        findings.extend(self._unregistered_task_findings(tasks_tree, tree_entries))
        return findings

    def _tree_finding(
        self,
        entry: _TreeEntry,
        tasks_tree: RegistryNode | None,
        tasks_root: Path,
    ) -> Finding | None:
        """Build one finding naming every inconsistency this Tree entry carries."""
        guid_node = tasks_tree.child(entry.task_id) if tasks_tree is not None else None
        task_file = _task_file(tasks_root, _disk_task_path(guid_node, entry.task_path))

        anomalies: list[str] = []
        # "is False", not "not": safe_is_file answers None when it cannot tell,
        # and a task file the scan could not open is not a missing one.
        if task_file is None or safe_is_file(task_file) is False:
            anomalies.append(_NO_TASK_FILE)
        # A Tasks subtree the scan never loaded says nothing about any single Id.
        if tasks_tree is not None and guid_node is None:
            anomalies.append(_NO_TASKS_ENTRY)
        if not anomalies:
            return None

        return self._make_finding(
            path=f"HKLM\\SOFTWARE\\{entry.registry_path}",
            value=entry.task_id,
            access=AccessLevel.SYSTEM,
            description=_describe(entry.task_path, anomalies),
            time_evidence=_time_evidence(entry.task_path),
        )

    def _unregistered_task_findings(
        self,
        tasks_tree: RegistryNode | None,
        tree_entries: list[_TreeEntry],
    ) -> list[Finding]:
        """Report TaskCache\\Tasks GUIDs that no TaskCache\\Tree key registers."""
        if tasks_tree is None:
            return []

        registered_ids = {entry.task_id.lower() for entry in tree_entries}
        findings: list[Finding] = []
        for guid_name, guid_node in tasks_tree.children():
            if guid_name.lower() in registered_ids:
                continue
            task_path = _disk_task_path(guid_node, guid_name)
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_TASK_CACHE_TASKS}\\{guid_name}",
                    value=guid_name,
                    access=AccessLevel.SYSTEM,
                    description=_describe(task_path, [_NO_TREE_ENTRY]),
                    time_evidence=_time_evidence(task_path),
                )
            )
        return findings


@register_plugin
class HiddenScheduledTask(PersistencePlugin):
    """Flags TaskCache\\Tree keys whose security descriptor has been deleted."""

    definition = CheckDefinition(
        id="hidden_scheduled_task",
        technique="Hidden Scheduled Task",
        mitre_id="T1053.005",
        description=(
            "Deleting the SD value from a task's TaskCache\\Tree key, as the Tarrask "
            "malware does, hides a live scheduled task: it keeps its XML file, its "
            "triggers and its execution, but schtasks.exe and the Task Scheduler UI "
            "stop listing it. Every Tree key that registers a task carries an SD, so "
            "an absent or empty one is a deletion rather than a default."
        ),
        references=(
            "https://attack.mitre.org/techniques/T1053/005/",
            _TARRASK_REFERENCE,
        ),
    )

    def run(self) -> list[Finding]:
        """Report every TaskCache\\Tree key that registers a task but has no SD."""
        tree = self.context.load_subtree("SOFTWARE", _TASK_CACHE_TREE)
        if tree is None:
            return []

        return [
            self._make_finding(
                path=f"HKLM\\SOFTWARE\\{entry.registry_path}",
                value=entry.task_id,
                access=AccessLevel.SYSTEM,
                description=_describe(entry.task_path, [_NO_SECURITY_DESCRIPTOR]),
                time_evidence=_time_evidence(entry.task_path),
            )
            for entry in _tree_entries(tree)
            if not entry.has_security_descriptor
        ]
