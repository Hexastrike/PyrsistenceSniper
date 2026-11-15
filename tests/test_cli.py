"""Tests for the CLI: argument parsing, exit codes, and pipeline wiring."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pyrsistencesniper.cli import build_parser, main
from pyrsistencesniper.core import ledger
from pyrsistencesniper.core.models import CheckFailure, HiveRecord, HiveStatus

from .conftest import context_with, patched_scan


def test_build_parser_defaults() -> None:
    """Defaults define a no-flag run: console output, medium severity, no file."""
    parser = build_parser()
    args = parser.parse_args(["/fake/image"])
    assert args.path == Path("/fake/image")
    assert args.format == "console"
    assert args.output is None
    assert args.min_severity == "medium"
    assert args.verbose is False
    assert args.list_checks is False


def test_build_parser_all_flags() -> None:
    """Every flag lands on its own attribute, with --technique collecting a list."""
    parser = build_parser()
    args = parser.parse_args(
        [
            "/img",
            "--format",
            "csv",
            "--output",
            "out.csv",
            "--profile",
            "p.yaml",
            "--technique",
            "T1547",
            "T1546",
            "--min-severity",
            "info",
            "-v",
            "--hostname",
            "HOST1",
        ]
    )
    assert args.format == "csv"
    assert args.output == Path("out.csv")
    assert args.profile == Path("p.yaml")
    assert args.technique == ["T1547", "T1546"]
    assert args.min_severity == "info"
    assert args.verbose is True
    assert args.hostname == "HOST1"


def test_list_checks_output(capsys: pytest.CaptureFixture[str]) -> None:
    """--list-checks should print at least one registered check."""
    with patch("sys.argv", ["pyrsistencesniper", "--list-checks"]):
        main()
    out = capsys.readouterr().out
    assert "T1547" in out or "T1546" in out or "scheduled" in out.lower()


def test_main_empty_image_reports_incomplete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty directory is a failed scan, not a clean host."""
    # Nothing was read, so success would let a mistyped path or the wrong volume
    # of a multi-volume collection pass for a clean result.
    argv = ["pyrsistencesniper", str(tmp_path), "--format", "csv"]
    with patch("sys.argv", argv), pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    assert exc.value.code == 2
    assert "SOFTWARE" in captured.err
    assert "Error" not in captured.err


def test_build_parser_timeline_flags() -> None:
    """--mft parses to a Path and --no-timeline to a bool with sane defaults."""
    parser = build_parser()

    args = parser.parse_args(["/img", "--mft", "mft.bin"])
    assert args.mft == Path("mft.bin")
    assert args.no_timeline is False

    args = parser.parse_args(["/img", "--no-timeline"])
    assert args.mft is None
    assert args.no_timeline is True


def test_mft_nonexistent_path_exits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A --mft path that is not a file exits 1 and names the missing file."""
    missing = tmp_path / "absent.mft"
    argv = ["pyrsistencesniper", str(tmp_path), "--mft", str(missing)]
    with patch("sys.argv", argv), pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert str(missing) in capsys.readouterr().err


def test_mft_with_no_timeline_is_contradiction(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--mft together with --no-timeline exits 1 with a contradiction message."""
    argv = [
        "pyrsistencesniper",
        str(tmp_path),
        "--mft",
        str(tmp_path / "mft.bin"),
        "--no-timeline",
    ]
    with patch("sys.argv", argv), pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert "--mft cannot be combined with --no-timeline" in capsys.readouterr().err


def test_run_scan_threads_mft_and_timeline_to_pipeline(tmp_path: Path) -> None:
    """An externally collected $MFT and the timeline toggle reach the pipeline."""
    mft = tmp_path / "mft.bin"
    mft.write_bytes(b"")
    argv = ["pyrsistencesniper", str(tmp_path), "--mft", str(mft)]
    with (
        patch("sys.argv", argv),
        patch("pyrsistencesniper.cli.build_context"),
        patch("pyrsistencesniper.cli.DetectionProfile"),
        patch("pyrsistencesniper.cli.get_renderer"),
        patch(
            "pyrsistencesniper.cli.make_progress_bar",
            return_value=(MagicMock(), None),
        ),
        patch("pyrsistencesniper.cli.run_pipeline", return_value=[]) as mock_run,
    ):
        main()

    _args, kwargs = mock_run.call_args
    assert kwargs["mft_path"] == mft
    assert kwargs["timeline"] is True


def test_unreadable_hive_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A hive that would not open makes the scan exit non-zero."""
    context = context_with(
        HiveRecord(name="SYSTEM", status=HiveStatus.OPEN_FAILED, error="OSError: bad")
    )
    argv = ["pyrsistencesniper", str(tmp_path)]

    with (
        patch("sys.argv", argv),
        patched_scan(context),
        pytest.raises(SystemExit) as exc,
    ):
        main()

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "SYSTEM: OPEN_FAILED: OSError: bad" in err
    assert not any(line.startswith("Error:") for line in err.splitlines())


def test_failed_check_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A check that never ran fails the scan even when every hive opened."""
    context = context_with(HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED))
    argv = ["pyrsistencesniper", str(tmp_path)]

    with (
        patch("sys.argv", argv),
        patched_scan(context),
        patch(
            "pyrsistencesniper.cli.ledger.failures",
            return_value=(CheckFailure(check_id="run_keys", error="OSError: bad"),),
        ),
        pytest.raises(SystemExit) as exc,
    ):
        main()

    assert exc.value.code == 2
    assert "run_keys: OSError: bad" in capsys.readouterr().err


def test_partially_read_key_exits_two_and_reaches_the_renderer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key read only in part is lost coverage, named by the key and not a check."""
    context = context_with(HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED))
    ledger.record_partial_read("Run", "OSError: bad cell")
    argv = ["pyrsistencesniper", str(tmp_path)]

    with (
        patch("sys.argv", argv),
        patched_scan(context) as get_renderer,
        pytest.raises(SystemExit) as exc,
    ):
        main()

    assert exc.value.code == 2
    assert "registry key Run: OSError: bad cell" in capsys.readouterr().err
    _args, kwargs = get_renderer.return_value.return_value.render.call_args
    assert kwargs["failures"] == (
        CheckFailure(artifact="registry key Run", error="OSError: bad cell"),
    )


def test_failed_check_reaches_the_renderer(tmp_path: Path) -> None:
    """Failed checks are handed to the renderer, so a written report carries them."""
    context = context_with(HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED))
    argv = ["pyrsistencesniper", str(tmp_path)]
    failures = (CheckFailure(check_id="ghost_task", error="ValueError: boom"),)

    with (
        patch("sys.argv", argv),
        patched_scan(context) as get_renderer,
        patch("pyrsistencesniper.cli.ledger.failures", return_value=failures),
        pytest.raises(SystemExit),
    ):
        main()

    _args, kwargs = get_renderer.return_value.return_value.render.call_args
    assert kwargs["failures"] == failures


def test_readable_hives_exit_zero(tmp_path: Path) -> None:
    """A scan whose hives all opened returns normally."""
    context = context_with(HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED))
    argv = ["pyrsistencesniper", str(tmp_path)]

    with patch("sys.argv", argv), patched_scan(context):
        main()


def test_uncollected_hive_is_not_a_failure(tmp_path: Path) -> None:
    """A hive the image never contained does not fail the scan."""
    # Legitimate targets ship without SAM or SECURITY, and a standalone hive has
    # no machine hives at all.
    context = context_with(
        HiveRecord(name="SAM", status=HiveStatus.NOT_COLLECTED),
        HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED),
    )
    argv = ["pyrsistencesniper", str(tmp_path)]

    with patch("sys.argv", argv), patched_scan(context):
        main()


def test_repaired_hive_is_not_a_failure(tmp_path: Path) -> None:
    """A hive recovered by repair counts as read, not as a failure."""
    context = context_with(
        HiveRecord(name="SYSTEM", status=HiveStatus.REPAIRED, dirty=True)
    )
    argv = ["pyrsistencesniper", str(tmp_path)]

    with patch("sys.argv", argv), patched_scan(context):
        main()


def test_renderer_receives_the_hive_inventory(tmp_path: Path) -> None:
    """The inventory reaches the renderer so the report can show it."""
    records = (HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED),)
    context = context_with(*records)
    argv = ["pyrsistencesniper", str(tmp_path)]

    with patch("sys.argv", argv), patched_scan(context) as get_renderer:
        main()

    _args, kwargs = get_renderer.return_value.return_value.render.call_args
    assert kwargs["inventory"] == records


def test_renderer_receives_the_hostname(tmp_path: Path) -> None:
    """The hostname reaches the renderer so a row about the scan names its host."""
    context = context_with(HiveRecord(name="SOFTWARE", status=HiveStatus.OPENED))
    context.hostname = "HOST1"
    argv = ["pyrsistencesniper", str(tmp_path)]

    with patch("sys.argv", argv), patched_scan(context) as get_renderer:
        main()

    _args, kwargs = get_renderer.return_value.return_value.render.call_args
    assert kwargs["hostname"] == "HOST1"
