"""Tests for the TaskCache consistency checks: ghost and hidden tasks (T1053.005)."""

from __future__ import annotations

import errno
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from pyrsistencesniper.core.models import AccessLevel, Finding, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import RegistryNode
from pyrsistencesniper.plugins.T1053.ghost_task import GhostTask, HiddenScheduledTask

from .conftest import make_deps, make_node, setup_keys

# On a clean Windows 11 all 290 TaskCache\Tree keys that register a task carry an
# SD value. A fixture omitting it looks like the Tarrask deletion that
# hidden_scheduled_task reports, so every ghost fixture below supplies one.
_SECURITY_DESCRIPTOR = b"\x01\x00\x04\x80" + b"\x00" * 88

_TREE_SUBKEY = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
_TASKS_SUBKEY = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
_TREE_KEY = (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
)
_TASKS_KEY = (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
)

# A task Windows itself ships under Microsoft\Windows, the folder the ghost_task
# allow rule covers.
_BUILTIN_TASK_FOLDERS = ("Microsoft", "Windows", ".NET Framework")
_BUILTIN_TASK_NAME = ".NET Framework NGEN v4.0.30319"


def _ghost_task(
    tmp_path: Path,
    tree_node: RegistryNode | None,
    tasks_node: RegistryNode | None = None,
) -> GhostTask:
    """Build a GhostTask over a hive answering only the TaskCache keys given."""
    context, registry, _filesystem = make_deps(tmp_path)
    context.registry = registry
    plugin = GhostTask(context=context)
    setup_keys(plugin, _task_cache_keys(tree_node, tasks_node))
    return plugin


def _hidden_task(tmp_path: Path, tree_node: RegistryNode | None) -> HiddenScheduledTask:
    """Build a HiddenScheduledTask over a hive answering only TaskCache\\Tree."""
    context, registry, _filesystem = make_deps(tmp_path)
    context.registry = registry
    plugin = HiddenScheduledTask(context=context)
    setup_keys(plugin, _task_cache_keys(tree_node, None))
    return plugin


def _task_cache_keys(
    tree_node: RegistryNode | None, tasks_node: RegistryNode | None
) -> dict[str, object]:
    """Map the two TaskCache key paths to the nodes a test wants answered."""
    keys: dict[str, object] = {}
    if tree_node is not None:
        keys[_TREE_SUBKEY] = tree_node
    if tasks_node is not None:
        keys[_TASKS_SUBKEY] = tasks_node
    return keys


def _tasks_directory(tmp_path: Path) -> Path:
    """Create and return the System32\\Tasks directory the ghost check reads."""
    tasks_directory = tmp_path / "Windows" / "System32" / "Tasks"
    tasks_directory.mkdir(parents=True)
    return tasks_directory


def _task_tree(task_name: str, **values: object) -> RegistryNode:
    """Build a TaskCache\\Tree holding one task key carrying the given values."""
    return make_node(
        name="Tree", children={task_name: make_node(name=task_name, values=values)}
    )


def _tasks_key(guid: str, **values: object) -> RegistryNode:
    """Build a TaskCache\\Tasks holding one GUID key carrying the given values."""
    return make_node(name="Tasks", children={guid: make_node(name=guid, values=values)})


def _nested(leaf: RegistryNode, *folders: str) -> RegistryNode:
    """Wrap a task key in the Tree folders that name it, outermost returned."""
    node = leaf
    for folder in reversed(folders):
        node = make_node(name=folder, children={node.name: node})
    return make_node(name="Tree", children={node.name: node})


def test_ghost_task_detected(tmp_path: Path) -> None:
    """A TaskCache entry with no task file on disk is what schtasks cannot show."""
    _tasks_directory(tmp_path)
    tree_node = _task_tree("EvilTask", Id="{GUID-123}", SD=_SECURITY_DESCRIPTOR)

    findings = _ghost_task(tmp_path, tree_node).run()

    assert len(findings) == 1
    assert "{GUID-123}" in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert findings[0].path == f"{_TREE_KEY}\\EvilTask"


def test_ghost_task_reads_the_taskcache_tree_key_and_no_other(tmp_path: Path) -> None:
    """A hive answering some other key path must yield nothing at all."""
    _tasks_directory(tmp_path)
    decoy_tree = _task_tree("EvilTask", Id="{GUID-DECOY}")

    context, registry, _filesystem = make_deps(tmp_path)
    context.registry = registry
    plugin = GhostTask(context=context)
    setup_keys(plugin, {"Microsoft\\Windows NT\\CurrentVersion\\Schedule": decoy_tree})

    assert plugin.run() == []


def test_task_with_xml_not_flagged(tmp_path: Path) -> None:
    """A task backed by its XML file is ordinary and must not be reported."""
    (_tasks_directory(tmp_path) / "LegitTask").write_text("<Task/>")

    tree_node = _task_tree("LegitTask", Id="{GUID-OK}", SD=_SECURITY_DESCRIPTOR)
    tasks_node = _tasks_key("{GUID-OK}", Path="\\LegitTask")

    assert _ghost_task(tmp_path, tree_node, tasks_node).run() == []


def test_multiple_ghost_tasks(tmp_path: Path) -> None:
    """Two registry entries with no corresponding XML files produce two findings."""
    _tasks_directory(tmp_path)

    child_a = make_node(
        name="TaskA", values={"Id": "{GUID-A}", "SD": _SECURITY_DESCRIPTOR}
    )
    child_b = make_node(
        name="TaskB", values={"Id": "{GUID-B}", "SD": _SECURITY_DESCRIPTOR}
    )
    tree_node = make_node(name="Tree", children={"TaskA": child_a, "TaskB": child_b})

    findings = _ghost_task(tmp_path, tree_node).run()

    assert len(findings) == 2
    found_values = {finding.value for finding in findings}
    assert "{GUID-A}" in found_values
    assert "{GUID-B}" in found_values
    for finding in findings:
        assert finding.access_gained == AccessLevel.SYSTEM
        assert finding.mitre_id == "T1053.005"
        assert finding.path.startswith("HKLM\\SOFTWARE\\")


def test_absolute_registry_path_cannot_escape_tasks_directory(tmp_path: Path) -> None:
    """An absolute Path value must not satisfy the on-disk check via the host."""
    _tasks_directory(tmp_path)
    decoy = tmp_path / "planted.xml"
    decoy.write_text("<Task/>")

    tree_node = _task_tree("Hidden", Id="{GUID-ESCAPE}", SD=_SECURITY_DESCRIPTOR)
    tasks_node = _tasks_key("{GUID-ESCAPE}", Path=str(decoy))

    findings = _ghost_task(tmp_path, tree_node, tasks_node).run()

    assert [finding.value for finding in findings] == ["{GUID-ESCAPE}"]


def test_traversing_registry_path_cannot_escape_tasks_directory(
    tmp_path: Path,
) -> None:
    """A traversing Path value must not satisfy the on-disk check."""
    _tasks_directory(tmp_path)
    (tmp_path / "Windows" / "System32" / "outside.xml").write_text("<Task/>")

    tree_node = _task_tree("Hidden", Id="{GUID-TRAVERSE}", SD=_SECURITY_DESCRIPTOR)
    tasks_node = _tasks_key("{GUID-TRAVERSE}", Path=r"..\outside.xml")

    findings = _ghost_task(tmp_path, tree_node, tasks_node).run()

    assert [finding.value for finding in findings] == ["{GUID-TRAVERSE}"]


def test_oversized_registry_path_does_not_kill_the_check(tmp_path: Path) -> None:
    """A hostile oversized Path value reports the task instead of raising."""
    _tasks_directory(tmp_path)

    tree_node = _task_tree("Hidden", Id="{GUID-BIG}", SD=_SECURITY_DESCRIPTOR)
    tasks_node = _tasks_key("{GUID-BIG}", Path="\\" + "A" * 40000)

    findings = _ghost_task(tmp_path, tree_node, tasks_node).run()

    assert [finding.value for finding in findings] == ["{GUID-BIG}"]


def test_nul_bearing_registry_path_does_not_kill_the_check(tmp_path: Path) -> None:
    """A Path value with an embedded NUL reports the task instead of raising."""
    _tasks_directory(tmp_path)

    tree_node = _task_tree("Hidden", Id="{GUID-NUL}", SD=_SECURITY_DESCRIPTOR)
    tasks_node = _tasks_key("{GUID-NUL}", Path="evil\x00.job")

    findings = _ghost_task(tmp_path, tree_node, tasks_node).run()

    assert [finding.value for finding in findings] == ["{GUID-NUL}"]


def _plugin_with_one_unbacked_task(tmp_path: Path) -> GhostTask:
    """Wire one task with no XML, so the tri-state pair differs only in the answer."""
    _tasks_directory(tmp_path)
    tree_node = _task_tree(
        "TriStateTask", Id="{GUID-TRISTATE}", SD=_SECURITY_DESCRIPTOR
    )
    return _ghost_task(tmp_path, tree_node)


def test_unreadable_task_file_is_not_reported_as_a_ghost_task(tmp_path: Path) -> None:
    """A task XML that will not open (WinError 1392) is not evidence it is missing."""
    plugin = _plugin_with_one_unbacked_task(tmp_path)

    with patch(
        "pyrsistencesniper.plugins.T1053.ghost_task.safe_is_file",
        return_value=None,
    ) as undeterminable_is_file:
        findings = plugin.run()

    assert findings == []
    # The tasks-root gate is guarded by safe_is_dir, deliberately left unpatched;
    # one call here proves the plugin reached the per-task check rather than
    # returning early for an unrelated reason.
    assert undeterminable_is_file.call_count == 1


def test_absent_task_file_is_still_reported_when_the_check_can_answer(
    tmp_path: Path,
) -> None:
    """The control: a definite "not a file" is a ghost, so None and False differ."""
    plugin = _plugin_with_one_unbacked_task(tmp_path)

    with patch(
        "pyrsistencesniper.plugins.T1053.ghost_task.safe_is_file",
        return_value=False,
    ) as absent_is_file:
        findings = plugin.run()

    assert [finding.value for finding in findings] == ["{GUID-TRISTATE}"]
    assert absent_is_file.call_count == 1


def test_unreadable_tasks_directory_reports_nothing(tmp_path: Path) -> None:
    """An unreadable Tasks directory ends the check; only the ledger records it."""
    _tasks_directory(tmp_path)
    tree_node = _task_tree("TriStateTask", Id="{GUID-NOROOT}", SD=_SECURITY_DESCRIPTOR)
    plugin = _ghost_task(tmp_path, tree_node)

    with patch(
        "pyrsistencesniper.plugins.T1053.ghost_task.safe_is_dir",
        return_value=None,
    ):
        assert plugin.run() == []


def test_unresolvable_task_path_is_reported_as_a_ghost_task(tmp_path: Path) -> None:
    """Known limitation: _task_file cannot tell a swallowed OSError from an escape."""
    tasks_directory = _tasks_directory(tmp_path)
    # The task really is on disk, so an unpatched run reports nothing at all;
    # the finding below can only come from the swallowed resolve failure.
    (tasks_directory / "UnreadableTask").write_text("<Task/>")

    tree_node = _task_tree(
        "UnreadableTask", Id="{GUID-UNRESOLVABLE}", SD=_SECURITY_DESCRIPTOR
    )
    plugin = _ghost_task(tmp_path, tree_node)

    unpatched_resolve = Path.resolve

    def _resolve_refusing_the_task(self: Path, *args, **kwargs) -> Path:
        """Fail the way a virtual-disk driver does, but only for the task path."""
        if "UnreadableTask" in self.parts:
            raise OSError(errno.EINVAL, "The device does not recognize the command")
        return unpatched_resolve(self, *args, **kwargs)

    with patch.object(Path, "resolve", _resolve_refusing_the_task):
        findings = plugin.run()

    assert [finding.value for finding in findings] == ["{GUID-UNRESOLVABLE}"]


def _fully_registered_task(
    tmp_path: Path,
    *,
    tree_values: dict[str, object],
    with_tasks_key: bool = True,
) -> tuple[RegistryNode, RegistryNode]:
    """Build one task registered in all three places, varying only its Tree values."""
    (_tasks_directory(tmp_path) / "SyncTask").write_text("<Task/>")

    tree_node = make_node(
        name="Tree",
        children={"SyncTask": make_node(name="SyncTask", values=tree_values)},
    )
    guid_node = make_node(name="{GUID-SYNC}", values={"Path": "\\SyncTask"})
    tasks_node = make_node(
        name="Tasks",
        children={"{GUID-SYNC}": guid_node} if with_tasks_key else {},
    )
    return tree_node, tasks_node


def test_tree_entry_without_a_tasks_key_is_reported(tmp_path: Path) -> None:
    """A Tree Id no Tasks key answers for is a half-deleted or half-planted task."""
    tree_node, tasks_node = _fully_registered_task(
        tmp_path,
        tree_values={"Id": "{GUID-SYNC}", "Index": 3, "SD": _SECURITY_DESCRIPTOR},
        with_tasks_key=False,
    )

    findings = _ghost_task(tmp_path, tree_node, tasks_node).run()

    assert [finding.value for finding in findings] == ["{GUID-SYNC}"]
    assert "no TaskCache\\Tasks key" in findings[0].description


def test_missing_tasks_subtree_does_not_accuse_every_tree_entry(
    tmp_path: Path,
) -> None:
    """A Tasks subtree never loaded must not accuse every registered task at once."""
    (_tasks_directory(tmp_path) / "SyncTask").write_text("<Task/>")
    tree_node = _task_tree("SyncTask", Id="{GUID-SYNC}", SD=_SECURITY_DESCRIPTOR)

    # With no TaskCache\Tasks tree the on-disk path falls back to the task name,
    # which is how a task backed by its XML file stays quiet here.
    assert _ghost_task(tmp_path, tree_node).run() == []


def test_one_finding_per_tree_entry_however_many_anomalies(tmp_path: Path) -> None:
    """All 32 built-in ghost tasks have both anomalies; a row each would double them."""
    _tasks_directory(tmp_path)
    tree_node = _task_tree("EvilTask", Id="{GUID-ALL}", SD=_SECURITY_DESCRIPTOR)

    findings = _ghost_task(tmp_path, tree_node, make_node(name="Tasks")).run()

    assert len(findings) == 1
    description = findings[0].description
    assert "no task XML file" in description
    assert "no TaskCache\\Tasks key" in description


def test_tasks_key_with_no_tree_entry_is_reported(tmp_path: Path) -> None:
    """A Tasks GUID no Tree key registers is never walked by a Tree-only check."""
    _tasks_directory(tmp_path)

    tree_node = make_node(name="Tree", children={})
    tasks_node = _tasks_key(
        "{GUID-ORPHAN}",
        Path="\\EvilTask",
        Actions=b"\x03\x00",
        Triggers=b"\x15\x00",
    )

    findings = _ghost_task(tmp_path, tree_node, tasks_node).run()

    assert [finding.value for finding in findings] == ["{GUID-ORPHAN}"]
    assert findings[0].path == f"{_TASKS_KEY}\\{{GUID-ORPHAN}}"
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert "EvilTask" in findings[0].description


def test_tasks_key_registered_by_a_tree_entry_is_not_reported(tmp_path: Path) -> None:
    """All 258 Tasks GUIDs on a clean host have a Tree key, matched case-blind."""
    (_tasks_directory(tmp_path) / "SyncTask").write_text("<Task/>")

    tree_node = _task_tree("SyncTask", Id="{guid-sync}", SD=_SECURITY_DESCRIPTOR)
    tasks_node = _tasks_key("{GUID-SYNC}", Path="\\SyncTask")

    assert _ghost_task(tmp_path, tree_node, tasks_node).run() == []


def test_nested_task_folders_are_walked(tmp_path: Path) -> None:
    """Built-in tasks sit two folders deep, so the Tree walk must recurse."""
    _tasks_directory(tmp_path)

    leaf = make_node(
        name="AitAgent", values={"Id": "{GUID-NESTED}", "SD": _SECURITY_DESCRIPTOR}
    )
    tree_node = _nested(leaf, "Microsoft", "Windows", "Application Experience")

    findings = _ghost_task(tmp_path, tree_node).run()

    assert [finding.path for finding in findings] == [
        f"{_TREE_KEY}\\Microsoft\\Windows\\Application Experience\\AitAgent"
    ]


def test_deleted_security_descriptor_is_not_a_ghost_task_finding(
    tmp_path: Path,
) -> None:
    """Under ghost_task's folder allowlist a Tarrask SD deletion classified INFO."""
    tree_node, tasks_node = _fully_registered_task(
        tmp_path, tree_values={"Id": "{GUID-SYNC}", "Index": 3}
    )

    assert _ghost_task(tmp_path, tree_node, tasks_node).run() == []


def test_builtin_windows_ghost_tasks_stay_below_the_report_threshold(
    tmp_path: Path,
) -> None:
    """Removing this allow rule once produced 32 false positives on a clean Win 11."""
    _tasks_directory(tmp_path)

    leaf = make_node(
        name="AitAgent", values={"Id": "{GUID-BUILTIN}", "SD": _SECURITY_DESCRIPTOR}
    )
    tree_node = _nested(leaf, "Microsoft", "Windows", "Application Experience")

    findings = _ghost_task(tmp_path, tree_node, make_node(name="Tasks")).run()
    assert len(findings) == 1

    policy = DetectionProfile.load(None).policy_for("ghost_task")
    # The resolution stage answers is_lolbin before the profile classifies; a
    # raw plugin finding still carries None, which no not_lolbin rule matches.
    resolved: Finding = replace(findings[0], is_lolbin=False)

    assert policy.classify(resolved) is Severity.INFO


def test_ghost_task_outside_the_builtin_folders_still_reaches_the_report(
    tmp_path: Path,
) -> None:
    """The control for the rule above: an attacker's own folder is not suppressed."""
    _tasks_directory(tmp_path)
    tree_node = _task_tree("EvilTask", Id="{GUID-EVIL}", SD=_SECURITY_DESCRIPTOR)

    findings = _ghost_task(tmp_path, tree_node, make_node(name="Tasks")).run()
    assert len(findings) == 1

    policy = DetectionProfile.load(None).policy_for("ghost_task")
    resolved: Finding = replace(findings[0], is_lolbin=False)

    assert policy.classify(resolved) >= Severity.MEDIUM


def test_absent_taskcache_tree_reports_nothing(tmp_path: Path) -> None:
    """An image whose SOFTWARE hive has no TaskCache at all yields no findings."""
    assert _ghost_task(tmp_path, None).run() == []


def _hidden_builtin_task(**tree_values: object) -> RegistryNode:
    """Build the live Microsoft\\Windows task the measurement was taken against."""
    leaf = make_node(
        name=_BUILTIN_TASK_NAME,
        values={"Id": "{7EA770C3-6028-45AC-8AB7-A986A54AD5B0}", **tree_values},
    )
    return _nested(leaf, *_BUILTIN_TASK_FOLDERS)


def test_deleted_security_descriptor_is_reported(tmp_path: Path) -> None:
    """Tarrask hides a live task by deleting the SD value off its Tree key."""
    tree_node = _hidden_builtin_task(Index=3)

    findings = _hidden_task(tmp_path, tree_node).run()

    assert [finding.value for finding in findings] == [
        "{7EA770C3-6028-45AC-8AB7-A986A54AD5B0}"
    ]
    assert findings[0].path == (
        f"{_TREE_KEY}\\Microsoft\\Windows\\.NET Framework"
        "\\.NET Framework NGEN v4.0.30319"
    )
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert "no SD value" in findings[0].description


def test_empty_security_descriptor_is_reported(tmp_path: Path) -> None:
    """Emptying the SD value hides the task just as deleting it does."""
    tree_node = _hidden_builtin_task(Index=3, SD=b"")

    findings = _hidden_task(tmp_path, tree_node).run()

    assert [finding.value for finding in findings] == [
        "{7EA770C3-6028-45AC-8AB7-A986A54AD5B0}"
    ]


def test_task_with_its_security_descriptor_is_not_reported(tmp_path: Path) -> None:
    """The control: every one of the 290 Tree keys on a clean host keeps its SD."""
    tree_node = _hidden_builtin_task(Index=3, SD=_SECURITY_DESCRIPTOR)

    assert _hidden_task(tmp_path, tree_node).run() == []


def test_unreadable_security_descriptor_type_is_not_called_a_deletion(
    tmp_path: Path,
) -> None:
    """An SD the hive parser hands back as an int is still an SD, not a deletion."""
    tree_node = _hidden_builtin_task(Index=3, SD=1)

    assert _hidden_task(tmp_path, tree_node).run() == []


def test_hidden_task_under_microsoft_windows_reaches_the_report(
    tmp_path: Path,
) -> None:
    """Measured live: INFO as a ghost_task finding, MEDIUM under its own check id."""
    tree_node = _hidden_builtin_task(Index=3)

    findings = _hidden_task(tmp_path, tree_node).run()
    assert len(findings) == 1

    profile = DetectionProfile.load(None)
    resolved: Finding = replace(findings[0], is_lolbin=False)
    hidden_severity = profile.policy_for("hidden_scheduled_task").classify(resolved)
    ghost_severity = profile.policy_for("ghost_task").classify(resolved)

    assert hidden_severity >= Severity.MEDIUM
    assert ghost_severity is Severity.INFO


def test_hidden_task_needs_no_tasks_directory_on_the_image(tmp_path: Path) -> None:
    """Inheriting ghost_task's Tasks-directory gate would silence a standalone hive."""
    tree_node = _hidden_builtin_task(Index=3)
    assert not (tmp_path / "Windows" / "System32" / "Tasks").exists()

    findings = _hidden_task(tmp_path, tree_node).run()

    assert [finding.value for finding in findings] == [
        "{7EA770C3-6028-45AC-8AB7-A986A54AD5B0}"
    ]


def test_hidden_task_check_reads_the_taskcache_tree_key_and_no_other(
    tmp_path: Path,
) -> None:
    """A hive answering only some other key path must yield nothing at all."""
    decoy_tree = _task_tree("EvilTask", Id="{GUID-DECOY}")

    context, registry, _filesystem = make_deps(tmp_path)
    context.registry = registry
    plugin = HiddenScheduledTask(context=context)
    setup_keys(plugin, {_TASKS_SUBKEY: decoy_tree})

    assert plugin.run() == []


def test_hidden_task_check_walks_nested_folders(tmp_path: Path) -> None:
    """A task hidden three folders deep is found by the same recursive walk."""
    leaf = make_node(name="AitAgent", values={"Id": "{GUID-NESTED}"})
    tree_node = _nested(leaf, "Microsoft", "Windows", "Application Experience")

    findings = _hidden_task(tmp_path, tree_node).run()

    assert [finding.path for finding in findings] == [
        f"{_TREE_KEY}\\Microsoft\\Windows\\Application Experience\\AitAgent"
    ]


def test_hidden_task_check_ignores_folder_keys_that_register_no_task(
    tmp_path: Path,
) -> None:
    """Tree folder keys carry no Id and no SD, and are not hidden tasks."""
    leaf = make_node(
        name="AitAgent", values={"Id": "{GUID-FOLDER}", "SD": _SECURITY_DESCRIPTOR}
    )
    tree_node = _nested(leaf, "Microsoft", "Windows", "Application Experience")

    assert _hidden_task(tmp_path, tree_node).run() == []


def test_hidden_task_check_reports_nothing_without_a_taskcache_tree(
    tmp_path: Path,
) -> None:
    """An image whose SOFTWARE hive has no TaskCache at all yields no findings."""
    assert _hidden_task(tmp_path, None).run() == []
