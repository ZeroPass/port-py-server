import logging
from typing import Optional, TypeVar

logging.SUCCESS = 25  # between WARNING and INFO
logging.addLevelName(logging.SUCCESS, 'SUCCESS')

logging.VERBOSE = 5  # between NOTSET and DEBUG
logging.addLevelName(logging.VERBOSE, 'VERBOSE')
LogLevelType = TypeVar("LogLevelType", int, str)

from logging import ( #pylint: disable=wrong-import-position
    FileHandler,
    Formatter,
    getLevelName,
    VERBOSE,
    DEBUG,
    INFO,
    SUCCESS,
    WARNING,
    ERROR,
    FATAL,
    CRITICAL
)

__all__ = [
    "FileHandler",
    "Formatter",
    "getLevelName",
    "LogLevelType",
    "VERBOSE",
    "DEBUG",
    "INFO",
    "SUCCESS",
    "WARNING",
    "ERROR",
    "FATAL",
    "CRITICAL"
]


def getLogger(name = None, logLevel: Optional[LogLevelType] = None) -> logging.Logger:
    """
    Install Log class as default logging class and returns new or existing logger by name.
    Note: this will install Log as default logging class for all loggers
    """
    if logging.getLoggerClass() != Log:
        logging.setLoggerClass(Log)
    l = logging.getLogger(name)
    if logLevel:
        if isinstance(logLevel, str):
            logLevel = logLevel.upper()
        l.setLevel(logLevel)
    return l

class Log(logging.Logger):
    def success(self, msg, *args, **kw):
        if self.isEnabledFor(SUCCESS):
            self._log(SUCCESS, msg, args, **kw)

    def verbose(self, msg, *args, **kw):
        if self.isEnabledFor(VERBOSE):
            self._log(VERBOSE, msg, args, **kw)
