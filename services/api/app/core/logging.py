"""Structured logging configuration using structlog."""

import logging
import sys

import structlog

from app.core.config import is_dev_env, settings


def configure_logging() -> None:
    """Configure structlog for structured JSON logging in production."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    # Previously this used ``settings.ENV == "development"`` — an exact-match
    # string compare that silently skipped the console renderer for the other
    # dev aliases (``dev``, ``local``, ``demo``, ``test``). Routing to
    # ``is_dev_env`` keeps a single source of truth for what "this is a
    # development-class environment" means across the service.
    if is_dev_env(settings.ENV):
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Silence noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str = __name__) -> structlog.BoundLogger:
    return structlog.get_logger(name)


# Maximum length for a single user-derived value embedded in a log line.
# Keeps logs readable and bounds memory if a caller passes pathological input.
_MAX_LOG_VALUE_LEN = 256

# Characters that can be used to forge log entries, break log parsers, or
# inject ANSI escape sequences when logs are rendered to a terminal.
_LOG_INJECTION_TRANSLATE = str.maketrans(
    {
        "\r": "\\r",
        "\n": "\\n",
        "\t": "\\t",
        "\x00": "\\x00",
        "\x1b": "\\x1b",
    }
)


def safe_log_value(value: object, max_len: int = _MAX_LOG_VALUE_LEN) -> str:
    """Sanitize an arbitrary value before embedding it in a log message.

    Defends against log-injection (CWE-117) by escaping characters that can
    forge new log entries (CR/LF/NUL/ESC) and by truncating overly long
    user-controlled strings. Use whenever a log statement interpolates a value
    that originated from an HTTP request, header, query string, or JSON body.
    """
    if value is None:
        return "<none>"
    text = str(value).translate(_LOG_INJECTION_TRANSLATE)
    if len(text) > max_len:
        text = text[:max_len] + "...<truncated>"
    return text
