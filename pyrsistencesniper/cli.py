from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.image import ForensicImage
from pyrsistencesniper.core.log import setup_logging
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import RegistryHelper
from pyrsistencesniper.output import get_renderer
from pyrsistencesniper.plugins import (
    _PLUGIN_REGISTRY,
    _discover_plugins,
    run_all_checks,
)


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the argparse parser for the pyrsistencesniper CLI."""
    parser = argparse.ArgumentParser(
        prog="pyrsistencesniper",
        description=(
            "Detect Windows persistence mechanisms from offline forensic artifacts."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Image root directory or individual artifact files",
    )
    parser.add_argument(
        "--hostname",
        type=str,
        default="",
        help="Override hostname (otherwise read from SYSTEM hive)",
    )
    parser.add_argument(
        "--format",
        choices=["console", "csv", "html"],
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
        "--raw",
        action="store_true",
        help="Disable all suppression (OS filters and allow rules)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging to stderr",
    )
    parser.add_argument(
        "--log-format",
        type=str,
        default=None,
        help="Override the log line format string",
    )
    return parser


def main() -> None:
    """Parse arguments, run the detection pipeline, and render output."""
    from pyrsistencesniper.banner import print_banner

    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    setup_logging(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        fmt=args.log_format,
    )

    if args.list_checks:
        _list_checks()
        return

    if args.update_lolbins:
        from pyrsistencesniper.core.lolbins import download_lolbins

        download_lolbins()
        return

    if not args.paths:
        parser.error("the following arguments are required: paths")

    image_root = args.paths[0]
    registry = RegistryHelper()
    image = ForensicImage(
        root=image_root,
        hostname_override=args.hostname,
        registry=registry,
    )
    filesystem = FilesystemHelper(image_root=image_root)
    profile = (
        DetectionProfile.load(args.profile)
        if args.profile
        else DetectionProfile.default()
    )

    console = Console(stderr=True)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        disable=not sys.stderr.isatty(),
    ) as prog:
        current_task_id = None
        current_stage: str | None = None
        current_total: int = 0

        def on_progress(stage: str, current: int, total: int) -> None:
            nonlocal current_task_id, current_stage, current_total
            if stage != current_stage:
                if current_task_id is not None:
                    prog.update(current_task_id, completed=current_total)
                current_task_id = prog.add_task(stage, total=total)
                current_stage = stage
            current_total = total
            if current_task_id is not None:
                prog.update(current_task_id, completed=current)

        results = run_all_checks(
            image=image,
            registry=registry,
            filesystem=filesystem,
            profile=profile,
            technique_filter=tuple(args.technique),
            raw=args.raw,
            progress=on_progress,
        )

    renderer_cls = get_renderer(args.format)
    renderer = renderer_cls()
    renderer.render(results, output=args.output)


def _list_checks() -> None:
    """Discover all plugins and print their IDs, MITRE mappings, and technique names."""
    _discover_plugins()
    if not _PLUGIN_REGISTRY:
        print("No checks registered.")
        return
    for _check_id, plugin_cls in sorted(_PLUGIN_REGISTRY.items()):
        defn = plugin_cls.definition
        print(f"{defn.id:<30s} [{defn.mitre_id}] {defn.technique}")
