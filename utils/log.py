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
    for logger in cfg.cfg:
        _cfg = cfg[logger]

        if logger == 'root':
            logger = None

        print("Logging to the file: %s" % _cfg['file'])
        for handler in reversed(log.getLogger(logger).handlers):
            log.getLoggerloggerremoveHandler(handler)
        err_handler = log.StreamHandler(sys.__stderr__)
        err_handler.setLevel(log.WARNING)
        log.getLogger(logger).addHandler(err_handler)
        file_handler = RotatingFileHandler(_cfg['file'], maxBytes=_cfg['max_file_size'], backupCount=_cfg['max_files'])
        formatter = log.Formatter(_cfg['format'])
        formatter.converter = time.gmtime
        file_handler.setFormatter(formatter)
        log.getLogger(logger).addHandler(file_handler)
        log_level = _LOG_LEVEL[_cfg['level']]
        log.getLogger(logger).setLevel(log_level)
        log.info("========================= Starting application =========================")
