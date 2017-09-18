'''
Configures logging subsystem.
'''
import logging as log
from logging.handlers import RotatingFileHandler
import sys

import time

_LOG_LEVEL = {
    'critical': log.CRITICAL,
    'error': log.ERROR,
    'warning': log.WARNING,
    'info': log.INFO,
    'debug': log.DEBUG
}


async def config(cfg):
    """
    Logging configuration
    """
    print("Logging to the file: %s" % cfg['file'])
    for handler in reversed(log.getLogger().handlers):
        log.getLogger().removeHandler(handler)
    err_handler = log.StreamHandler(sys.__stderr__)
    err_handler.setLevel(log.WARNING)
    log.getLogger().addHandler(err_handler)
    file_handler = RotatingFileHandler(cfg['file'], maxBytes=cfg['max_file_size'], backupCount=cfg['max_files'])
    formatter = log.Formatter(cfg['format'])
    formatter.converter = time.gmtime
    file_handler.setFormatter(formatter)
    log.getLogger().addHandler(file_handler)
    log_level = _LOG_LEVEL[cfg['level']]
    log.getLogger().setLevel(log_level)
    log.info("========================= Starting application =========================")
