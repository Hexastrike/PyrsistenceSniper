from __future__ import annotations

from collections.abc import Callable

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.discovery import build_context

ProgressFn = Callable[[str, int, int], None]

__all__ = ["AnalysisContext", "ProgressFn", "build_context", "run_all_checks"]


def __getattr__(name: str) -> object:
    if name == "run_all_checks":
        from pyrsistencesniper.core.pipeline import run_all_checks

        return run_all_checks
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
