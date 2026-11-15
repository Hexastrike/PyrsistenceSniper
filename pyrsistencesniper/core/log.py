"""Configure the package logger."""

# Package-wide logging policy. A failure that costs the run a whole check,
# artifact or hive is a WARNING naming what was lost plus a DEBUG carrying the
# traceback. A failure recovered from without losing coverage is a DEBUG with
# exc_info=True. Silence is correct only in a helper whose contract is to
# report failure through its return value.

from __future__ import annotations

import logging
import sys

_DEFAULT_FMT = "%(asctime)s %(levelname)-8s %(name)s - %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"


class _CurrentStderrHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """A stderr handler that re-resolves the stream on every record."""

    def emit(self, record: logging.LogRecord) -> None:
        """Write the record to whatever sys.stderr is at this moment."""
        # The progress bar puts a Rich live region on stderr and swaps sys.stderr
        # for a proxy while it is up. Logging is configured long before that, so a
        # handler holding the stream it was built with writes past the proxy and
        # lands inside the region: the bars are repainted below the log line and
        # the whole block appears twice. Re-resolving sends the record through the
        # proxy, which prints it above the bars and leaves them in place.
        self.stream = sys.stderr
        super().emit(record)


def setup_logging(
    level: int = logging.WARNING,
    fmt: str | None = None,
) -> None:
    """Configure a stderr handler on the pyrsistencesniper logger."""
    logger = logging.getLogger("pyrsistencesniper")
    logger.setLevel(level)

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    handler = _CurrentStderrHandler()
    handler.setFormatter(
        logging.Formatter(fmt or _DEFAULT_FMT, datefmt=_DEFAULT_DATEFMT)
    )
    logger.addHandler(handler)
