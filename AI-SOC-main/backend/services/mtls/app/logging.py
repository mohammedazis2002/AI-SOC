import logging
from enum import StrEnum

LOG_FORMAT_DEBUG = "%(levelname)s:%(message)s:%(pathname)s:%(funcName)s:%(lineno)d"


class Log_Levels(StrEnum):
    info = "INFO"
    warn = "WARN"
    error = "ERROR"
    debug = "DEBUG"


def configure_logging(log_level: str = Log_Levels.error):
    log_level = str(log_level).upper()
    log_levels = [level.value for level in Log_Levels]

    if log_level not in log_levels:
        logging.basicConfig(level=Log_Levels.error)
        return

    if log_level == Log_Levels.debug:
        logging.basicConfig(level=log_level, format=LOG_FORMAT_DEBUG)
        return

    logging.basicConfig(level=log_level)
