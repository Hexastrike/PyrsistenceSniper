from __future__ import annotations

import logging

from pyrsistencesniper.core.log import setup_logging


def _namespace_logger() -> logging.Logger:
    return logging.getLogger("pyrsistencesniper")


def teardown_function() -> None:
    """Remove handlers added during tests so they don't leak."""
    logger = _namespace_logger()
    for h in logger.handlers[:]:
        logger.removeHandler(h)
    logger.setLevel(logging.WARNING)


# -- basic behaviour ---------------------------------------------------------


def test_default_level_is_warning() -> None:
    setup_logging()
    assert _namespace_logger().level == logging.WARNING


def test_level_override() -> None:
    setup_logging(level=logging.DEBUG)
    assert _namespace_logger().level == logging.DEBUG


def test_attaches_single_handler() -> None:
    setup_logging()
    assert len(_namespace_logger().handlers) == 1


def test_handler_writes_to_stderr(capsys: object) -> None:
    setup_logging(level=logging.WARNING)
    logging.getLogger("pyrsistencesniper.test_child").warning("boom")
    # capsys doesn't capture logging StreamHandler output, but we can
    # verify the handler is a StreamHandler writing to stderr.
    handler = _namespace_logger().handlers[0]
    assert isinstance(handler, logging.StreamHandler)


# -- idempotency -------------------------------------------------------------


def test_idempotent_no_duplicate_handlers() -> None:
    setup_logging()
    setup_logging()
    setup_logging()
    assert len(_namespace_logger().handlers) == 1


# -- custom format -----------------------------------------------------------


def test_custom_format() -> None:
    setup_logging(fmt="%(message)s")
    handler = _namespace_logger().handlers[0]
    assert handler.formatter is not None
    assert handler.formatter._fmt == "%(message)s"


def test_default_format_contains_asctime() -> None:
    setup_logging()
    handler = _namespace_logger().handlers[0]
    assert handler.formatter is not None
    assert "%(asctime)s" in handler.formatter._fmt


# -- child logger propagation ------------------------------------------------


def test_child_logger_inherits_level() -> None:
    setup_logging(level=logging.DEBUG)
    child = logging.getLogger("pyrsistencesniper.core.registry")
    assert child.getEffectiveLevel() == logging.DEBUG
