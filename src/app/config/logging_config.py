"""
src/app/config/logging_config.py

Logging destinations:
  - stdout → Fluentd sidecar → Loki (all environments; retention driven by LOKI_RETENTION_DAYS)
  - Rotating file (app.log, 10 MB × 5 backups, ~50 MB cap) — non-production only

Access control: Loki is on the operator network only; no external port exposed.
Retention policy: controlled by LOKI_RETENTION_DAYS in .env (see .agent/ docs for the wider inventory).
"""

import logging
import logging.handlers
import json
import os
import re
import threading
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

# Context variable to hold the correlation ID for each request/task
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="N/A")

# Lock protecting LOGGING_CONFIG dict mutations in update_logging_level (V15.4.1)
_logging_lock = threading.Lock()

# Patterns used by RedactionFilter to detect sensitive values in log records
_REDACT_PATTERNS = [
    re.compile(
        r"(?i)(password|secret|token|api[_-]?key|authorization|bearer|fernet|cookie)"
        r"['\"]?\s*[:=]\s*['\"][^'\"]+['\"]"
    ),
    re.compile(r"eyJ[A-Za-z0-9._-]+"),  # JWT shape
    re.compile(r"\b[A-Za-z0-9+/=]{40,}\b"),  # high-entropy base64 strings
]


class RedactionFilter(logging.Filter):
    """
    Logging filter that scrubs known secret patterns from log records before emission.
    Protects passwords, tokens, API keys, JWTs, and high-entropy strings. (V14.1.2)
    """

    def _scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            for pattern in _REDACT_PATTERNS:
                value = pattern.sub("***REDACTED***", value)
        return value

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._scrub(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._scrub(a) for a in record.args)
        # Scrub any extra attributes injected via extra={...}
        for attr, val in list(record.__dict__.items()):
            if attr not in logging.LogRecord.__dict__ and isinstance(val, str):
                setattr(record, attr, self._scrub(val))
        return True


# Built-in LogRecord attributes the formatter should NOT echo as "extras".
# Anything else on the record came from a `logger.x("msg", extra={...})`
# call site and is what we want to surface.
_STANDARD_LOGRECORD_ATTRS: frozenset[str] = frozenset(
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
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)

# Cap total extras serialised per record so a runaway payload (e.g. a
# huge validation-error blob) can't blow up Loki ingestion. Tuned for
# the typical "errors": [...] list — generous, but bounded.
_MAX_EXTRA_BYTES = 8192


def _sanitise_log_value(value: Any) -> Any:
    """Recursively scrub CR/LF from any string buried in the value, so
    a multi-line payload can't smear across log lines (V16.4.1). Lists,
    tuples, and dicts are walked; other types pass through untouched
    and rely on `json.dumps(default=str)` for stringification."""
    if isinstance(value, str):
        return value.replace("\r", "\\r").replace("\n", "\\n")
    if isinstance(value, dict):
        return {k: _sanitise_log_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitise_log_value(v) for v in value]
    return value


class JSONFormatter(logging.Formatter):
    """
    Custom logging formatter to output logs in a structured JSON format.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Emit UTC ISO-8601 timestamp for SIEM/LOKI correlation (V16.2.2)
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
            timespec="milliseconds"
        )

        # Sanitise CR/LF from caller-supplied message to prevent log injection (V16.4.1)
        raw_message = record.getMessage()
        safe_message = raw_message.replace("\r", "\\r").replace("\n", "\\n")

        # Create a dictionary with standard log attributes
        log_object: dict[str, Any] = {
            "timestamp": ts,
            "level": record.levelname,
            "message": safe_message,
            "logger_name": record.name,
            "func_name": record.funcName,
            "correlation_id": correlation_id_var.get(),
            "service_name": os.getenv("SERVICE_NAME", "unknown"),
        }

        # Add exception info if it exists; sanitise newlines for log-injection defence
        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            log_object["exc_info"] = exc_text.replace("\r", "\\r").replace("\n", "\\n")

        # Merge `extra={...}` kwargs from the call site. Standard logging
        # attaches each `extra` key as a LogRecord attribute, so we walk
        # `record.__dict__`, skip the built-ins, and emit the rest under
        # their own JSON keys. Without this, every `logger.x("msg",
        # extra={"errors": ...})` call line is logged with the headline
        # only — the payload silently drops.
        for attr, val in record.__dict__.items():
            if attr in _STANDARD_LOGRECORD_ATTRS:
                continue
            if attr in log_object:
                # Don't let an extras key clobber a standard field
                # (timestamp / level / correlation_id / etc.).
                continue
            try:
                serialised = json.dumps(_sanitise_log_value(val), default=str)
            except (TypeError, ValueError):
                # Last-resort: stringify unknown objects rather than
                # losing the whole log line to a serialisation error.
                serialised = json.dumps(repr(val))
            if len(serialised) > _MAX_EXTRA_BYTES:
                # Replace oversized payloads with a marker rather than
                # truncating mid-string (which would emit invalid JSON
                # via json.loads on the consumer side).
                log_object[attr] = (
                    f"<extra '{attr}' dropped: "
                    f"{len(serialised)} bytes > {_MAX_EXTRA_BYTES} cap>"
                )
            else:
                log_object[attr] = json.loads(serialised)

        return json.dumps(log_object, default=str)


# Determine the running environment; default to "production" when unset (fail-safe) (V13.4.2)
_ENVIRONMENT = os.getenv("ENVIRONMENT", "production").lower()
_IS_PRODUCTION = _ENVIRONMENT == "production"

# Log file path for non-production environments (V14.2.4)
_LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "app.log")

# Apply restrictive file permissions on the log file at startup (V14.2.4)
# This runs at import time so the file exists before any handler opens it.
if not _IS_PRODUCTION:
    try:
        _log_dir = os.path.dirname(os.path.abspath(_LOG_FILE_PATH))
        os.makedirs(_log_dir, exist_ok=True)
        # Touch the file if it doesn't yet exist so chmod can be applied
        if not os.path.exists(_LOG_FILE_PATH):
            open(_LOG_FILE_PATH, "a").close()
        os.chmod(_LOG_FILE_PATH, 0o600)
    except OSError:
        # Read-only worker images (least-privilege pentest processes) cannot
        # create a log file; logging simply stays on console handlers.
        pass

# Active app logger level: INFO in production, DEBUG elsewhere (V13.4.2 / V14.1.2)
_APP_LOG_LEVEL = "INFO" if _IS_PRODUCTION else "DEBUG"

# Handlers included for the app logger — file handler only in non-production (V13.4.2 / V16.2.3)
_APP_HANDLERS = ["default"] if _IS_PRODUCTION else ["default", "file"]

# The main logging configuration dictionary
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": JSONFormatter,
        },
    },
    "filters": {
        # Redaction filter removes passwords/tokens/keys from every log record (V14.1.2)
        "redact": {
            "()": RedactionFilter,
        },
    },
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "filters": ["redact"],
            "stream": "ext://sys.stdout",
        },
        # Rotating file handler: 10 MB × 5 files (~50 MB cap) guards disk exhaustion
        # (V14.2.4, V14.2.7, V15.1.3, V15.2.2). Only active in non-production (V13.4.2).
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "json",
            "filters": ["redact"],
            "filename": _LOG_FILE_PATH,
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 5,
        },
    },
    "loggers": {
        "app": {"handlers": _APP_HANDLERS, "level": _APP_LOG_LEVEL, "propagate": False},
        "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.error": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.access": {
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },
        "sqlalchemy": {"handlers": ["default"], "level": "WARNING", "propagate": False},
        "aio_pika": {"handlers": ["default"], "level": "WARNING", "propagate": False},
        "aiormq": {"handlers": ["default"], "level": "WARNING", "propagate": False},
        "py.warnings": {
            "handlers": ["default"],
            "level": "WARNING",
            "propagate": False,
        },
        "langgraph": {"handlers": ["default"], "level": "INFO", "propagate": False},
        # Root logger — stdout only; file handler is app-logger-scoped above
        "": {"handlers": ["default"], "level": "INFO"},
    },
}


def update_logging_level(level: str):
    """
    Dynamically updates the logging level for the 'app' and root loggers.

    Thread-safe: LOGGING_CONFIG dict mutations and logger.setLevel calls are
    performed inside _logging_lock so concurrent requests cannot observe a
    partially-updated state. (V15.4.1)
    """
    level = level.upper()
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if level not in valid_levels:
        raise ValueError(f"Invalid log level: {level}")

    with _logging_lock:
        # Update the configuration dictionary (for future reference if needed)
        LOGGING_CONFIG["loggers"]["app"]["level"] = level
        LOGGING_CONFIG["loggers"][""]["level"] = level

        # Apply changes to active loggers
        logger = logging.getLogger("app")
        logger.setLevel(level)
        logging.getLogger().setLevel(level)

        # Also update specific third-party loggers if we want them to be verbose in DEBUG
        # However, for now let's keep it simple and just update the main app loggers
        # as too much noise from libraries can be overwhelming.

        logger.info(f"Log level updated to {level}")
