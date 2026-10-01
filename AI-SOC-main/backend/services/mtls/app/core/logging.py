import logging
import sys
from enum import StrEnum


LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | %(name)s | " "%(pathname)s:%(lineno)d | %(message)s"
)


class LogLevel(StrEnum):
    debug = "DEBUG"
    info = "INFO"
    warning = "WARNING"
    error = "ERROR"


def configure_logging(level: LogLevel = LogLevel.info) -> None:
    root = logging.getLogger()

    # Avoid duplicate handlers
    if root.handlers:
        root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(LOG_FORMAT)
    handler.setFormatter(formatter)

    root.setLevel(level.value)
    root.addHandler(handler)
