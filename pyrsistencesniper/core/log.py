"""Logging configuration for the pyrsistencesniper package."""

from __future__ import annotations

import logging
import sys

_DEFAULT_FMT = "%(asctime)s %(levelname)-8s %(name)s - %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    level: int = logging.WARNING,
    fmt: str | None = None,
) -> None:
    """Configure a stderr handler on the pyrsistencesniper logger."""
    logger = logging.getLogger("pyrsistencesniper")
    logger.setLevel(level)

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(fmt or _DEFAULT_FMT, datefmt=_DEFAULT_DATEFMT)
    )
    logger.addHandler(handler)
