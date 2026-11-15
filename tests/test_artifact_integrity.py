"""Tests for the artifact integrity channel that names artifacts no check parsed."""

from __future__ import annotations

import errno
import io
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from defusedxml.ElementTree import ParseError
from pyrsistencesniper.cli import main
from pyrsistencesniper.core.ledger import (
    artifact_failures,
    record_artifact_failure,
    reset,
)
from pyrsistencesniper.core.models import CheckFailure, HiveRecord, HiveStatus
from pyrsistencesniper.output.console_output import ConsoleOutput

from .conftest import context_with, patched_scan

_TASK_XML = r"C:\Windows\System32\Tasks\Microsoft\Windows\Foo\Bar"
_SCRIPTS_INI = r"C:\Windows\System32\GroupPolicy\Machine\Scripts\scripts.ini"


def test_unparseable_artifact_is_reported_as_lost_coverage() -> None:
    """A task XML that exists but will not parse becomes a reportable failure."""
    record_artifact_failure(
        "scheduled_tasks", Path(_TASK_XML), ParseError("no element found: line 1")
    )

    (failure,) = artifact_failures()
    assert failure.check_id == "scheduled_tasks"
    assert failure.artifact == _TASK_XML
    assert failure.error == "ParseError: no element found: line 1"


def test_missing_artifact_stays_quiet() -> None:
    """An artifact the image never held is a real negative and is never reported."""
    record_artifact_failure(
        "scheduled_tasks",
        Path(_TASK_XML),
        FileNotFoundError(errno.ENOENT, "No such file or directory"),
    )

    assert artifact_failures() == ()


def test_artifact_below_a_file_stays_quiet() -> None:
    """A path walked through a file is absence, not coverage the scan lost."""
    record_artifact_failure(
        "gp_scripts",
        Path(_SCRIPTS_INI),
        NotADirectoryError(errno.ENOTDIR, "Not a directory"),
    )

    assert artifact_failures() == ()


def test_artifact_that_exists_but_will_not_open_is_reported() -> None:
    """A refused read is coverage lost, unlike a file that was never there."""
    record_artifact_failure(
        "scheduled_tasks",
        Path(_TASK_XML),
        PermissionError(errno.EACCES, "Access is denied"),
    )

    (failure,) = artifact_failures()
    assert failure.error == "PermissionError: [Errno 13] Access is denied"


def test_failure_without_an_exception_is_reported() -> None:
    """A read that exhausts every encoding has no exception and still costs coverage."""
    record_artifact_failure("gp_scripts", _SCRIPTS_INI, "all encoding attempts failed")

    (failure,) = artifact_failures()
    assert failure.error == "all encoding attempts failed"


def test_one_artifact_failing_twice_is_reported_once() -> None:
    """A retried artifact is one gap in the report, not one line per attempt."""
    record_artifact_failure("scheduled_tasks", Path(_TASK_XML), ValueError("boom"))
    record_artifact_failure("scheduled_tasks", Path(_TASK_XML), ValueError("boom"))

    assert len(artifact_failures()) == 1


def test_two_checks_failing_on_one_artifact_are_both_reported() -> None:
    """Each check that lost the artifact is named, because each lost its coverage."""
    record_artifact_failure("scheduled_tasks", Path(_TASK_XML), ValueError("boom"))
    record_artifact_failure("ghost_task", Path(_TASK_XML), ValueError("boom"))

    reported = {failure.label for failure in artifact_failures()}
    assert reported == {
        f"ghost_task artifact {_TASK_XML}",
        f"scheduled_tasks artifact {_TASK_XML}",
    }


def test_reset_forgets_an_earlier_scans_artifact_failures() -> None:
    """The ledger is scoped to one scan, so a stale gap cannot leak into the next."""
    record_artifact_failure("scheduled_tasks", Path(_TASK_XML), ValueError("boom"))
    reset()

    assert artifact_failures() == ()


def test_console_names_the_artifact_that_would_not_parse() -> None:
    """An empty console report says which artifact was never read."""
    record_artifact_failure(
        "scheduled_tasks", Path(_TASK_XML), ParseError("no element found: line 1")
    )
    out = io.StringIO()

    ConsoleOutput()._write([], out, failures=artifact_failures())
    text = out.getvalue()

    assert "SCAN INCOMPLETE" in text
    assert "artifact" in text
    assert _TASK_XML in text
    assert "ParseError: no element found: line 1" in text
    assert "No findings." in text


def test_console_stays_quiet_when_every_artifact_parsed() -> None:
    """A scan that read every artifact gets no integrity banner."""
    out = io.StringIO()

    ConsoleOutput()._write([], out, failures=())

    assert "SCAN INCOMPLETE" not in out.getvalue()


def _scan_that_loses(check_id: str, artifact: str) -> Callable[..., list[object]]:
    """Return a run_pipeline stand-in that loses one artifact mid-scan."""

    def run(*_args: object, **_kwargs: object) -> list[object]:
        record_artifact_failure(check_id, artifact, ParseError("no element found"))
        return []

    return run


def _intact_scan(*_args: object, **_kwargs: object) -> list[object]:
    """Stand in for a scan that read every artifact and found nothing."""
    return []


def _scanned_context() -> MagicMock:
    """Return a context whose only hive opened, so hives cannot fail the run."""
    return context_with(HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED))


def test_unparseable_artifact_reaches_the_renderer(tmp_path: Path) -> None:
    """The written report carries the artifact gap, not just an empty finding list."""
    argv = ["pyrsistencesniper", str(tmp_path)]

    with (
        patch("sys.argv", argv),
        patched_scan(
            _scanned_context(),
            run_pipeline=_scan_that_loses("scheduled_tasks", _TASK_XML),
        ) as get_renderer,
        pytest.raises(SystemExit),
    ):
        main()

    _args, kwargs = get_renderer.return_value.return_value.render.call_args
    assert kwargs["failures"] == (
        CheckFailure(
            check_id="scheduled_tasks",
            artifact=_TASK_XML,
            error="ParseError: no element found",
        ),
    )


def test_unparseable_artifact_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An artifact the scan could not read fails the run even when every hive opened."""
    argv = ["pyrsistencesniper", str(tmp_path)]

    with (
        patch("sys.argv", argv),
        patched_scan(
            _scanned_context(),
            run_pipeline=_scan_that_loses("scheduled_tasks", _TASK_XML),
        ),
        pytest.raises(SystemExit) as exc,
    ):
        main()

    assert exc.value.code == 2
    assert _TASK_XML in capsys.readouterr().err


def test_scan_that_read_every_artifact_exits_zero(tmp_path: Path) -> None:
    """A clean scan stays exit 0, so the new channel cannot fail an intact run."""
    argv = ["pyrsistencesniper", str(tmp_path)]

    with (
        patch("sys.argv", argv),
        patched_scan(_scanned_context(), run_pipeline=_intact_scan) as get_renderer,
    ):
        main()

    _args, kwargs = get_renderer.return_value.return_value.render.call_args
    assert kwargs["failures"] == ()


def test_scan_forgets_an_earlier_scans_artifact_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A gap recorded before the scan is never reported as this scan's loss."""
    record_artifact_failure("scheduled_tasks", Path(_TASK_XML), ValueError("stale"))
    capsys.readouterr()
    argv = ["pyrsistencesniper", str(tmp_path), "--format", "csv"]

    with patch("sys.argv", argv), pytest.raises(SystemExit):
        main()

    assert "stale" not in capsys.readouterr().err
