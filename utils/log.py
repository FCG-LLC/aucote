'''
Configures logging subsystem.
'''
import logging as log
import sys


_LOG_LEVEL = {
    'critical': log.CRITICAL,
    'error': log.ERROR,
    'warning': log.WARNING,
    'info': log.INFO,
    'debug': log.DEBUG
}

def config(file_name, level):
    log_level = _LOG_LEVEL[level]
    print("Logging to the file: %s"%file_name)
    FORMAT = '%(levelname)s %(asctime)s %(threadName)s: %(message)s'
    err_handler = log.StreamHandler( sys.__stderr__ )
    err_handler.setLevel(log.WARNING)
    log.basicConfig(filename=file_name,level=log_level, format=FORMAT)
    log.getLogger().addHandler(err_handler)
    log.info("========================= Starting application =========================")