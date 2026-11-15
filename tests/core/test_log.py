"""Tests for setup_logging: namespace logger level, handler, and format."""

from __future__ import annotations

import io
import logging
import sys

import pytest
from pyrsistencesniper.core.log import setup_logging


def _namespace_logger() -> logging.Logger:
    """The package-root logger setup_logging configures; children inherit from it."""
    return logging.getLogger("pyrsistencesniper")


def teardown_function() -> None:
    """Remove handlers added during tests so they don't leak."""
    logger = _namespace_logger()
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    logger.setLevel(logging.WARNING)


def test_default_level_is_warning() -> None:
    """Without --verbose only the coverage-losing warnings reach the operator."""
    setup_logging()
    assert _namespace_logger().level == logging.WARNING


def test_level_override() -> None:
    """Raising the level is what surfaces the DEBUG tracebacks behind each warning."""
    setup_logging(level=logging.DEBUG)
    assert _namespace_logger().level == logging.DEBUG


def test_attaches_single_handler() -> None:
    """One handler means one line per record rather than a duplicated log."""
    setup_logging()
    assert len(_namespace_logger().handlers) == 1


def test_handler_writes_to_stderr() -> None:
    """Diagnostics on stderr leave stdout free for report output being piped."""
    setup_logging(level=logging.WARNING)
    logging.getLogger("pyrsistencesniper.test_child").warning("boom")
    handler = _namespace_logger().handlers[0]
    assert isinstance(handler, logging.StreamHandler)


def test_idempotent_no_duplicate_handlers() -> None:
    """A second call replaces the handler rather than doubling every log line."""
    setup_logging()
    setup_logging()
    setup_logging()
    assert len(_namespace_logger().handlers) == 1


def test_custom_format() -> None:
    """A caller's format replaces the default outright, timestamp prefix included."""
    setup_logging(fmt="%(message)s")
    handler = _namespace_logger().handlers[0]
    assert handler.formatter is not None
    assert handler.formatter._fmt == "%(message)s"


def test_default_format_contains_asctime() -> None:
    """Without a timestamp a warning cannot be placed against the rest of the run."""
    setup_logging()
    handler = _namespace_logger().handlers[0]
    assert handler.formatter is not None
    assert "%(asctime)s" in handler.formatter._fmt


def test_child_logger_inherits_level() -> None:
    """Module loggers need no setup; the namespace root carries the level down."""
    setup_logging(level=logging.DEBUG)
    child = logging.getLogger("pyrsistencesniper.core.registry")
    assert child.getEffectiveLevel() == logging.DEBUG


def test_handler_follows_a_replaced_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The progress bar swaps sys.stderr while it runs; the log must follow it."""
    # Binding the stream at setup time is what put a warning inside the Rich live
    # region and made the whole progress block render twice.
    setup_logging(level=logging.WARNING)
    replacement = io.StringIO()
    monkeypatch.setattr(sys, "stderr", replacement)
    logging.getLogger("pyrsistencesniper.test_child").warning("boom")
    assert "boom" in replacement.getvalue()
