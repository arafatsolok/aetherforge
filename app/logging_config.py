"""Structured logging configuration.

Uses structlog over stdlib logging so every log line is JSON when running
in production (easy to ship to ELK / Wazuh) and a pretty console renderer
in development.

Every log record carries:
  * timestamp      (ISO-8601 UTC, nanosecond precision)
  * level          (debug|info|warning|error|critical)
  * logger         (dotted module path)
  * event          (human string)
  * scan_id        (if bound via ``bind_scan_context``)
  * persona        (if bound)
  * target_id      (if bound)

Binding context is handled by ``structlog.contextvars`` — so async tasks
inherit it automatically across awaits.
"""

from __future__ import annotations

import logging
import logging.config
import sys
from typing import Any

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars
from structlog.types import EventDict, Processor

from app.config import Settings


def _drop_color_message_key(_logger: object, _method: str, event_dict: EventDict) -> EventDict:
    """Uvicorn adds a ``color_message`` duplicate; we don't need it."""
    event_dict.pop("color_message", None)
    return event_dict


def _rename_event_key(_logger: object, _method: str, event_dict: EventDict) -> EventDict:
    """Rename ``event`` -> ``message`` so Filebeat / ES treats it as the body."""
    event_dict["message"] = event_dict.pop("event", "")
    return event_dict


def configure_logging(settings: Settings) -> None:
    """Install structlog + stdlib logging handlers.

    Must be called exactly once at process start.
    """
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        _drop_color_message_key,
    ]

    if settings.is_development:
        renderer: Processor = structlog.dev.ConsoleRenderer(colors=True, pad_event_to=30)
    else:
        shared_processors.append(_rename_event_key)
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[settings.log_level]
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)

    # Quiet down noisy libraries.
    for name, level in {
        "uvicorn.access": "WARNING",
        "uvicorn.error": "INFO",
        "sqlalchemy.engine": "WARNING",
        "sqlalchemy.pool": "WARNING",
        "asyncio": "WARNING",
        "docker": "WARNING",
        "urllib3": "WARNING",
    }.items():
        logging.getLogger(name).setLevel(level)


def get_logger(name: str | None = None, **initial_context: Any) -> structlog.stdlib.BoundLogger:
    """Convenience wrapper — get a bound logger with optional context."""
    log = structlog.stdlib.get_logger(name)
    if initial_context:
        log = log.bind(**initial_context)
    return log


__all__ = [
    "bind_contextvars",
    "clear_contextvars",
    "configure_logging",
    "get_logger",
]
