from __future__ import annotations

import sys

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

from pyrsistencesniper.core import ProgressFn


def make_progress_bar() -> tuple[Progress, ProgressFn]:
    """Create a Rich progress bar and a callback that drives it.

    Returns the Progress context manager and a ProgressFn callback.
    The caller must use the Progress as a context manager::

        progress_bar, on_progress = make_progress_bar()
        with progress_bar:
            results = run_all_checks(ctx, progress=on_progress)
    """
    console = Console(stderr=True)
    prog = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        disable=not sys.stderr.isatty(),
    )

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

    return prog, on_progress
