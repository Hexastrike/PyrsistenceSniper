"""Command line entry point: argument parsing, logging, and scan dispatch."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from pyrsistencesniper.core.context import build_context
from pyrsistencesniper.core.filesystem import reset_skips, skipped_paths
from pyrsistencesniper.core.log import setup_logging
from pyrsistencesniper.core.lolbins import download_lolbins
from pyrsistencesniper.core.models import CheckFailure, HiveRecord, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import (
    artifact_failures,
    partial_reads,
    reset_artifact_failures,
    reset_partial_reads,
)
from pyrsistencesniper.core.windows import _io_path
from pyrsistencesniper.detection.pipeline import (
    failed_checks,
    reset_failures,
    run_pipeline,
)
from pyrsistencesniper.output import get_renderer
from pyrsistencesniper.plugins import (
    _PLUGIN_REGISTRY,
    _discover_plugins,
    reset_import_failures,
)
from pyrsistencesniper.ui.banner import print_banner
from pyrsistencesniper.ui.progress import make_progress_bar

_SEVERITY_CHOICES = tuple(level.name.lower() for level in Severity)

# Cap the skipped-path list so a long one cannot bury the report.
_MAX_SKIPPED_SHOWN = 5


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the argparse parser for the pyrsistencesniper CLI."""
    parser = argparse.ArgumentParser(
        prog="pyrsistencesniper",
        description=(
            "Detect Windows persistence mechanisms from offline forensic artifacts."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="Image root directory or standalone artifact file",
    )
    parser.add_argument(
        "--hostname",
        type=str,
        default="",
        help="Override hostname (otherwise read from SYSTEM hive)",
    )
    parser.add_argument(
        "--format",
        choices=["console", "csv", "html", "xlsx"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        help="YAML detection profile for allow/block overrides",
    )
    parser.add_argument(
        "--technique",
        nargs="+",
        default=[],
        help="Filter by MITRE ATT&CK IDs or check IDs",
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available checks and exit",
    )
    parser.add_argument(
        "--update-lolbins",
        action="store_true",
        help="Download the latest LOLBin list from the LOLBAS project and exit",
    )
    parser.add_argument(
        "--min-severity",
        choices=_SEVERITY_CHOICES,
        default="medium",
        help="Minimum severity to include in output (default: medium)",
    )
    parser.add_argument(
        "--mft",
        type=Path,
        default=None,
        help=(
            "Externally collected $MFT file for change timestamps "
            "(default: auto-discover inside the image root)"
        ),
    )
    parser.add_argument(
        "--no-timeline",
        action="store_true",
        help="Skip last-change timestamp resolution",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging to stderr",
    )
    return parser


def main() -> None:
    """Parse arguments, dispatch early-exit commands, or run the scan."""
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    setup_logging(
        level=logging.DEBUG if args.verbose else logging.WARNING,
    )

    if args.list_checks:
        _list_checks()
        return

    if args.update_lolbins:
        try:
            download_lolbins()
        except Exception as exc:
            _fail(logging.getLogger(__name__), exc)
        return

    if not args.path:
        parser.error("the following arguments are required: path")

    _run_scan(args)


def _fail(logger: logging.Logger, exc: Exception) -> None:
    """Report a fatal error on stderr and exit non-zero."""
    logger.debug("Fatal error details:", exc_info=True)
    sys.stderr.write(f"Error: {exc}\n")
    if not logger.isEnabledFor(logging.DEBUG):
        sys.stderr.write("Re-run with -v for a full traceback.\n")
    sys.exit(1)


def _run_scan(args: argparse.Namespace) -> None:
    """Build context, run the detection pipeline, and render output."""
    logger = logging.getLogger(__name__)

    if args.format == "xlsx" and not args.output:
        sys.stderr.write("Error: XLSX format requires --output <file>\n")
        sys.exit(1)

    if args.mft is not None and args.no_timeline:
        sys.stderr.write("Error: --mft cannot be combined with --no-timeline\n")
        sys.exit(1)

    if args.mft is not None and not _io_path(args.mft).is_file():
        sys.stderr.write(f"Error: $MFT file does not exist: {args.mft}\n")
        sys.exit(1)

    try:
        profile = DetectionProfile.load(args.profile)
        reset_skips()
        reset_failures()
        reset_import_failures()
        reset_partial_reads()
        reset_artifact_failures()
        context = build_context(args.path, hostname=args.hostname)

        progress_bar, on_progress = make_progress_bar()
        with progress_bar:
            results = run_pipeline(
                context,
                profile=profile,
                technique_filter=tuple(args.technique),
                min_severity=Severity[args.min_severity.upper()],
                mft_path=args.mft,
                timeline=not args.no_timeline,
                progress=on_progress,
            )

        inventory = context.hive_inventory()
        failures = failed_checks() + _partial_read_failures() + artifact_failures()
        renderer_cls = get_renderer(args.format)
        renderer = renderer_cls()
        renderer.render(
            results,
            output=args.output,
            inventory=inventory,
            failures=failures,
            hostname=context.hostname,
        )
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        _fail(logger, exc)

    _warn_on_skipped_paths()
    _exit_on_incomplete_scan(inventory, failures)


def _warn_on_skipped_paths() -> None:
    """Name paths the scan could not read, so an empty report is not read as clean."""
    skipped = skipped_paths()
    if not skipped:
        return
    shown = sorted(skipped)[:_MAX_SKIPPED_SHOWN]
    hidden = len(skipped) - _MAX_SKIPPED_SHOWN
    more = f" (+{hidden} more)" if hidden > 0 else ""
    sys.stderr.write(
        f"Warning: {len(skipped)} path(s) could not be read and were "
        f"skipped: {', '.join(shown)}{more}\n"
    )


def _partial_read_failures() -> tuple[CheckFailure, ...]:
    """Report partially-read registry keys as coverage the scan did not get."""
    return tuple(
        CheckFailure(artifact=f"registry key {key_name}", error=error)
        for key_name, error in sorted(partial_reads().items())
    )


def _exit_on_incomplete_scan(
    inventory: tuple[HiveRecord, ...],
    failures: tuple[CheckFailure, ...],
) -> None:
    """Name each hive, check or artifact that produced nothing, then exit non-zero."""
    unreadable = [record for record in inventory if record.cost_checks]

    if unreadable:
        sys.stderr.write(
            f"Scan incomplete: {len(unreadable)} hive(s) could not be read\n"
        )
        for record in unreadable:
            sys.stderr.write(f"  {record.label}: {record.outcome}\n")

    if failures:
        sys.stderr.write(
            f"Scan incomplete: {len(failures)} check(s) or artifact(s) "
            "produced nothing\n"
        )
        for failure in failures:
            sys.stderr.write(f"  {failure.label}: {failure.error}\n")

    if unreadable or failures:
        sys.exit(2)


def _list_checks() -> None:
    """Discover all plugins and print their IDs, MITRE mappings, and technique names."""
    _discover_plugins()
    if not _PLUGIN_REGISTRY:
        sys.stdout.write("No checks registered.\n")
        return
    for _check_id, plugin_cls in sorted(_PLUGIN_REGISTRY.items()):
        definition = plugin_cls.definition
        sys.stdout.write(
            f"{definition.id:<30s} [{definition.mitre_id}] {definition.technique}\n"
        )
