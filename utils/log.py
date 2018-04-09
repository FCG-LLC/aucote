"""
Configures logging subsystem.
"""
import logging as log
import sys
from pycslib.logger import setup_logger


# FixMe: update pycslib and reuse variables from it
LOG_LEVEL = {
    'critical': log.CRITICAL,
    'error': log.ERROR,
    'warning': log.WARNING,
    'info': log.INFO,
    'debug': log.DEBUG
}


async def config(cfg: dict):
    """
    Configure logging

    Args:
    cfg (Config): should contains configuration in format:

    .. code::

        logger_name:
            file: file path
            max_file_size: maximum size of log file
            max_files: maximum number of files
            format: format of logs
            level: logging level (INFO, WARNING, ERROR, CRITICAL or DEBUG)
            propagate: should configuration be propagated to parent logger

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

        setup_logger(name=logger, max_file_size=_cfg['max_file_size'], max_files=_cfg['max_files'],
                     log_format=_cfg['format'], filename=_cfg['file'], level=_cfg['level'], propagate=_cfg['propagate'])

        # Log errors to separate file
        for error_level in ('warning', 'error'):
            if LOG_LEVEL[_cfg['level']] < LOG_LEVEL[error_level]:
                setup_logger(name=logger, max_file_size=_cfg['max_file_size'], max_files=_cfg['max_files'],
                             log_format=_cfg['format'], filename=_cfg['file']+'.{}'.format(error_level.upper()),
                             level=error_level, propagate=_cfg['propagate'])

    log.info("========================= Starting application =========================")
