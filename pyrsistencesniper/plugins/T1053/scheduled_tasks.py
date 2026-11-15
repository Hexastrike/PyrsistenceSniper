"""Extract Exec and ComHandler actions from task XML files under System32\\Tasks."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

import defusedxml.ElementTree as DefusedET

from pyrsistencesniper.core.filesystem import (
    safe_is_dir,
    safe_is_file,
    safe_iterdir,
)
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    EventLogTime,
    FileWriteTime,
    Finding,
)
from pyrsistencesniper.core.registry import record_artifact_failure
from pyrsistencesniper.core.windows import _io_path
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_TASKS_DIR = r"Windows\System32\Tasks"
_TASKS_RELATIVE = Path(*_TASKS_DIR.split("\\"))
_MAX_DEPTH = 50


@register_plugin
class ScheduledTaskFiles(PersistencePlugin):
    """Detects Scheduled Task (XML Files) persistence entries."""

    definition = CheckDefinition(
        id="scheduled_task_files",
        technique="Scheduled Task (XML Files)",
        mitre_id="T1053.005",
        description=(
            "Scheduled task XML files under System32\\Tasks define the actions a task "
            "runs on its triggers: an Exec action starts a command line and a "
            "ComHandler action loads the COM server its CLSID registers."
        ),
        references=("https://attack.mitre.org/techniques/T1053/005/",),
    )

    def run(self) -> list[Finding]:
        """Parse scheduled task XML files and extract their executable actions."""
        findings: list[Finding] = []

        tasks_root = self._tasks_root()
        if not safe_is_dir(tasks_root):
            return findings

        self._walk_tasks(tasks_root, findings)
        return findings

    def _tasks_root(self) -> Path:
        """Return the System32\\Tasks directory under the image root."""
        return self.filesystem.image_root / _TASKS_RELATIVE

    def _walk_tasks(
        self,
        directory: Path,
        findings: list[Finding],
        depth: int = 0,
    ) -> None:
        """Recursively traverse the Tasks directory, parsing each XML file found."""
        if depth >= _MAX_DEPTH:
            return

        for entry in safe_iterdir(directory):
            if safe_is_dir(entry):
                self._walk_tasks(entry, findings, depth + 1)
            elif safe_is_file(entry):
                self._parse_task_xml(entry, findings)

    def _parse_task_xml(
        self,
        path: Path,
        findings: list[Finding],
    ) -> None:
        """Extract every Exec and ComHandler action from one task XML file."""
        try:
            tree = DefusedET.parse(_io_path(path))
        except Exception as exc:
            record_artifact_failure(self.definition.id, path, exc)
            return

        root = tree.getroot()
        namespace = ""
        if root.tag.startswith("{"):
            namespace = root.tag.split("}")[0] + "}"

        task_name = str(PureWindowsPath(path.relative_to(self._tasks_root())))

        for exec_element in root.iter(f"{namespace}Exec"):
            command = exec_element.findtext(f"{namespace}Command", "")
            arguments = exec_element.findtext(f"{namespace}Arguments", "")
            if not command:
                continue

            value = f"{command} {arguments}".strip() if arguments else command
            findings.append(self._task_finding(task_name, value))

        for com_element in root.iter(f"{namespace}ComHandler"):
            clsid = (com_element.findtext(f"{namespace}ClassId", "") or "").strip()
            image = self._com_server_image(clsid)
            if not image:
                continue

            findings.append(
                self._task_finding(
                    task_name,
                    image,
                    description=(
                        f"ComHandler action activating COM class {clsid} in the "
                        "Task Scheduler host process."
                    ),
                )
            )

    # A CLSID registering neither server is deliberately not emitted: it yields
    # nothing to hash, sign or classify, so the pipeline cannot assess it.
    def _com_server_image(self, clsid: str) -> str:
        """Resolve a ComHandler CLSID to the server image the scheduler would load."""
        if not clsid.startswith("{"):
            return ""

        hive = self.context.open_hive_by_name("SOFTWARE")
        if hive is None:
            return ""

        inproc_server = self.context.resolve_clsid_inproc(hive, clsid)
        if inproc_server:
            return inproc_server

        return self.context.resolve_clsid_default(
            hive, f"Classes\\CLSID\\{clsid}\\LocalServer32"
        )

    def _task_finding(
        self,
        task_name: str,
        value: str,
        description: str = "",
    ) -> Finding:
        """Build the finding for one task action, carrying the task's time evidence."""
        task_path = f"{_TASKS_DIR}\\{task_name}"
        event_key = f"\\{task_name}"
        return self._make_finding(
            path=task_path,
            value=value,
            access=AccessLevel.SYSTEM,
            description=description,
            time_evidence=(
                FileWriteTime(path=task_path),
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
            ),
        )
