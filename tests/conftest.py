"""Fixtures and builders shared by the whole suite."""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from pyrsistencesniper.core import ledger
from pyrsistencesniper.core.windows import io_path

if TYPE_CHECKING:
    from pathlib import Path

    from pyrsistencesniper.core.models import HiveRecord


@pytest.fixture(autouse=True)
def _clean_scan_ledger() -> Iterator[None]:
    """Empty the scan ledger around every test so entries cannot leak forward."""
    ledger.reset()
    yield
    ledger.reset()


def remove_over_length_tree(leaf_path: Path, stop_dir: Path) -> None:
    """Delete an over-length tree bottom-up, which rmtree cannot reach."""
    io_path(leaf_path).unlink(missing_ok=True)
    folder = leaf_path.parent
    while folder != stop_dir:
        with contextlib.suppress(OSError):
            io_path(folder).rmdir()
        folder = folder.parent


def context_with(*records: HiveRecord) -> MagicMock:
    """Return a fake analysis context whose hive inventory holds the given records."""
    context = MagicMock()
    context.hive_inventory.return_value = tuple(records)
    return context


@contextlib.contextmanager
def patched_scan(
    context: MagicMock,
    *,
    run_pipeline: Callable[..., list[object]] | None = None,
) -> Iterator[MagicMock]:
    """Patch every collaborator of a CLI scan and yield the renderer factory mock."""
    pipeline = (
        patch("pyrsistencesniper.cli.run_pipeline", return_value=[])
        if run_pipeline is None
        else patch("pyrsistencesniper.cli.run_pipeline", side_effect=run_pipeline)
    )
    with (
        patch("pyrsistencesniper.cli.build_context", return_value=context),
        patch("pyrsistencesniper.cli.DetectionProfile"),
        patch("pyrsistencesniper.cli.get_renderer") as get_renderer,
        patch(
            "pyrsistencesniper.cli.make_progress_bar",
            return_value=(MagicMock(), None),
        ),
        pipeline,
    ):
        yield get_renderer
