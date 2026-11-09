"""Standard library logging config for application logs: JSON lines, UTC, no secrets.

Security events go to Bower (bower_events.py), not here. Used by the Flask, FastAPI and
Django examples."""
import json
import logging
import re
import time

_CONTROL = re.compile("[\\x00-\\x1f\\x7f]")
_SECRET = re.compile("password|token|secret|authorization|cookie|body", re.IGNORECASE)


class JsonFormatter(logging.Formatter):
    converter = time.gmtime  # UTC (ASVS 5.0 V16.2.2)

    def format(self, record: logging.LogRecord) -> str:
        entry = {"time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z",
                 "level": record.levelname, "logger": record.name, "msg": _CONTROL.sub(" ", record.getMessage())}
        for key, value in getattr(record, "fields", {}).items():
            entry[key] = "[removed]" if _SECRET.search(key) else value
        return json.dumps(entry)  # JSON escapes CR and LF (V16.4.1)


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"json": {"()": JsonFormatter}},
    "handlers": {"stdout": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"handlers": ["stdout"], "level": "INFO"},
}
