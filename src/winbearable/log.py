"""Structured JSON logging configuration for winbearable."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, TextIO

from .const import ENV_LOG_FORMAT, ENV_LOG_LEVEL, ENV_LOG_PATH

LOGGER_ROOT_NAME = "winbearable"
LOG_FORMATS: tuple[str, ...] = ("json", "text")

_STANDARD_RECORD_ATTRS: frozenset[str] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

logging.getLogger(LOGGER_ROOT_NAME).addHandler(logging.NullHandler())


_SECRET_TEXT_RE = re.compile(r"(?i)(\b(?:bearer|token|password|passwd|secret|api[_-]?key)\b\s*[:=]\s*)([^\s,;\"']+)")
_WIN_USER_PATH_RE = re.compile(r"(?i)([A-Za-z]:\\Users\\)([^\\/\s\"']+)")


def redact_sensitive_text(text: str) -> str:
    """Redact common secret tokens and local Windows profile usernames from log strings."""
    masked = _SECRET_TEXT_RE.sub(r"\1<REDACTED>", text)
    return _WIN_USER_PATH_RE.sub(r"\1<USER>", masked)


def redact_sensitive_value(value: Any) -> Any:
    """Recursively redact sensitive strings inside structured log context."""
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, dict):
        return {
            k: (
                "<REDACTED>"
                if str(k).lower() in {"token", "password", "secret", "api_key"}
                else redact_sensitive_value(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_sensitive_value(v) for v in value]
    return value


class JsonLogFormatter(logging.Formatter):
    """Format log records as single-line JSON objects for stderr and log files."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_sensitive_text(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_ATTRS and not key.startswith("_") and key not in payload:
                payload[key] = (
                    "<REDACTED>"
                    if str(key).lower() in {"token", "password", "secret", "api_key"}
                    else redact_sensitive_value(value)
                )

        if record.exc_info and record.exc_info[0] is not None:
            payload.setdefault("error_type", record.exc_info[0].__name__)
            payload["exception"] = redact_sensitive_text(self.formatException(record.exc_info))
        elif record.exc_text:
            payload["exception"] = redact_sensitive_text(record.exc_text)

        return json.dumps(payload, default=str, ensure_ascii=False)


class _DynamicStderrHandler(logging.StreamHandler[TextIO]):
    """StreamHandler that tracks the current `sys.stderr` across redirections."""

    def __init__(self) -> None:
        super().__init__(sys.stderr)

    @property
    def stream(self) -> TextIO:
        return sys.stderr

    @stream.setter
    def stream(self, _value: TextIO) -> None:
        return


def _resolve_level(debug: bool, level: str | None) -> int:
    if debug:
        return logging.DEBUG
    raw = (level or os.environ.get(ENV_LOG_LEVEL, "") or "WARNING").strip().upper()
    resolved = logging.getLevelName(raw)
    if isinstance(resolved, int):
        return resolved
    return logging.WARNING


def _resolve_format(log_format: str | None) -> str:
    raw = (log_format or os.environ.get(ENV_LOG_FORMAT, "") or "json").strip().lower()
    return raw if raw in LOG_FORMATS else "json"


def _build_formatter(fmt: str) -> logging.Formatter:
    if fmt == "text":
        return logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    return JsonLogFormatter()


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the `winbearable` namespace."""
    if name == LOGGER_ROOT_NAME or name.startswith(f"{LOGGER_ROOT_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_ROOT_NAME}.{name}")


def reset_logging() -> None:
    """Close and remove all configured handlers on the package root logger."""
    root = logging.getLogger(LOGGER_ROOT_NAME)
    for handler in list(root.handlers):
        root.removeHandler(handler)
        if not isinstance(handler, logging.NullHandler):
            handler.close()
    root.addHandler(logging.NullHandler())


def configure_logging(
    *,
    debug: bool = False,
    log_format: str | None = None,
    log_file: str | Path | None = None,
    level: str | None = None,
) -> logging.Logger:
    """Configure structured logging on stderr and an optional rotating JSONL log file."""
    reset_logging()
    root = logging.getLogger(LOGGER_ROOT_NAME)
    root.propagate = False
    effective_level = _resolve_level(debug, level)
    root.setLevel(effective_level)

    fmt = _resolve_format(log_format)
    stderr_handler = _DynamicStderrHandler()
    stderr_handler.setLevel(effective_level)
    stderr_handler.setFormatter(_build_formatter(fmt))
    root.addHandler(stderr_handler)

    raw_file = str(log_file) if log_file is not None else os.environ.get(ENV_LOG_PATH, "").strip()
    if raw_file:
        path = Path(raw_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        file_handler.setLevel(min(effective_level, logging.INFO) if not debug else logging.DEBUG)
        file_handler.setFormatter(JsonLogFormatter())
        root.addHandler(file_handler)

    return root
