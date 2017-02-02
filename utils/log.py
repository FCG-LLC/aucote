'''
Configures logging subsystem.
'''
import logging as log
from logging.handlers import RotatingFileHandler
import sys

from os import getpid

_LOG_LEVEL = {
    'critical': log.CRITICAL,
    'error': log.ERROR,
    'warning': log.WARNING,
    'info': log.INFO,
    'debug': log.DEBUG
}


def config(cfg):
    """
    Logging configuration
    """
    print("Logging to the file: %s"%cfg['file'])
    err_handler = log.StreamHandler(sys.__stderr__)
    err_handler.setLevel(log.WARNING)
    log.getLogger().addHandler(err_handler)
    file_handler = RotatingFileHandler(cfg['file'], maxBytes=cfg['max_file_size'], backupCount=cfg['max_files'])
    formatter = log.Formatter(cfg['format'])
    file_handler.setFormatter(formatter)
    log.getLogger().addHandler(file_handler)
    log_level = _LOG_LEVEL[cfg['level']]
    log.getLogger().setLevel(log_level)
    log.info("========================= Starting application =========================")
