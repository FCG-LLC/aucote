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
    Configure logging

    Args:
        cfg (Config): should contains configuration in format:
            ```
            logger_name:
                file: file path
                max_file_size: maximum size of log file
                max_files: maximum number of files
                format: format of logs
                level: logging level (INFO, WARNING, ERROR, CRITICAL or DEBUG)
                propagate: should configuration be propagated to parent logger
            ```

    Returns:
        None

    """
    print("Logging to the file: %s" % cfg['root.file'])
    for handler in reversed(log.getLogger().handlers):
        log.getLogger().removeHandler(handler)
    err_handler = log.StreamHandler(sys.__stderr__)
    err_handler.setLevel(log.WARNING)
    log.getLogger().addHandler(err_handler)

    for logger in cfg.cfg:
        _cfg = cfg[logger]

        if logger == 'root':
            logger = None

        file_handler = RotatingFileHandler(_cfg['file'], maxBytes=_cfg['max_file_size'], backupCount=_cfg['max_files'])
        formatter = log.Formatter(_cfg['format'])
        formatter.converter = time.gmtime
        file_handler.setFormatter(formatter)
        log.getLogger(logger).addHandler(file_handler)
        log_level = _LOG_LEVEL[_cfg['level']]
        log.getLogger(logger).setLevel(log_level)
        log.getLogger(logger).propagate = _cfg['propagate']

        log.getLogger(logger).info("Logger %s configured", logger)

    log.info("========================= Starting application =========================")
