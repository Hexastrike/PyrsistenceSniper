from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from pyrsistencesniper.cli import build_parser, main


def test_build_parser_defaults() -> None:
    parser = build_parser()
    args = parser.parse_args(["/fake/image"])
    assert args.path == Path("/fake/image")
    assert args.format == "console"
    assert args.output is None
    assert args.min_severity == "medium"
    assert args.verbose is False
    assert args.list_checks is False


def test_build_parser_all_flags() -> None:
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


def test_list_checks(capsys: object) -> None:
    with patch("sys.argv", ["pyrsistencesniper", "--list-checks"]):
        main()
    # Just verify it didn't crash; list-checks prints to stdout


def test_list_checks_output(capsys: object) -> None:
    """--list-checks should print at least one registered check."""

    fixture = capsys  # type: ignore[assignment]
    with patch("sys.argv", ["pyrsistencesniper", "--list-checks"]):
        main()
    out = fixture.readouterr().out  # type: ignore[union-attr]
    assert "T1547" in out or "T1546" in out or "scheduled" in out.lower()


def test_main_empty_image_no_crash(tmp_path: Path, capsys: object) -> None:
    """Running against an empty directory should produce no findings and no crash."""
    fixture = capsys  # type: ignore[assignment]
    with patch("sys.argv", ["pyrsistencesniper", str(tmp_path), "--format", "csv"]):
        main()
    captured = fixture.readouterr()  # type: ignore[union-attr]
    assert "Error" not in captured.err


def test_main_with_min_severity_info(tmp_path: Path, capsys: object) -> None:
    """--min-severity info should include all findings without crashing."""
    fixture = capsys  # type: ignore[assignment]
    with patch(
        "sys.argv",
        [
            "pyrsistencesniper",
            str(tmp_path),
            "--format",
            "csv",
            "--min-severity",
            "info",
        ],
    ):
        main()
    captured = fixture.readouterr()  # type: ignore[union-attr]
    assert "Error" not in captured.err
