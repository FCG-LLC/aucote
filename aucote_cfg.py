'''
This module provides default configuration and the global instance for the utils.Config class.
'''
import os.path as path
from sys import stderr

import yaml

import utils.log as log_cfg
from utils import Config

# default values

LOG_DIR = path.join(path.dirname(__file__), 'logs')

_DEFAULT = {
    'logging': {
        'root': {
            'file': path.join(LOG_DIR, 'aucote.log'),
            'level': 'info',
            'max_file_size': 10 * 1024 * 1024,
            'max_files': 5,
            'format': '%(levelname)s %(asctime)s %(funcName)s: %(message)s',
            'propagate': True
        },
        'storage': {
            'file': path.join(LOG_DIR, 'storage.log'),
            'level': 'info',
            'max_file_size': 10 * 1024 * 1024,
            'max_files': 10,
            'format': '%(levelname)s %(asctime)s %(message)s',
            'propagate': False
        },
        'pycslib': {
            'file': path.join(LOG_DIR, 'pycslib.log'),
            'level': 'info',
            'max_file_size': 10 * 1024 * 1024,
            'max_files': 10,
            'format': '%(levelname)s %(asctime)s %(message)s',
            'propagate': False
        }
    },
    'fixtures': {
        'exploits': {
            'filename': 'fixtures/exploits/exploits.csv'
        }
    },
    'topdis': {
        'api': {
            'host': 'localhost',
            'port': 1234
        },
        'fetch_os': False
    },
    'toucan': {
        'enable': False,
        'api': 'http://toucan:3000',
        'min_retry_time': 5,
        'max_retry_time': 60 * 5,
        'max_retry_count': 20
    },
    'pid_file': 'aucote.pid',
    'default_config': 'aucote_cfg_default.yaml',
}

# global cfg
cfg = Config(_DEFAULT)


async def load(file_name=None):
    '''
    Initializes this module.
    Needs to be called before other functions are used.
    '''

    if file_name is None:
        # by default search for "confg.yaml" in application dir
        file_name = path.join(path.dirname(__file__), 'aucote_cfg.yaml')

    file_name = path.abspath(file_name)
    # at this point logs do not work, print info to stdout
    print("Reading configuration from file:", file_name)
    try:
        cfg.load(file_name, _DEFAULT)
    except Exception:
        stderr.write("Cannot load configuration file {0}".format(file_name))
        exit()

    await log_cfg.config(cfg['logging'])

    default_config_filename = cfg['default_config']

    try:
        cfg.load(default_config_filename, cfg.cfg)
    except Exception:
        stderr.write("Cannot load configuration file {0}".format(default_config_filename))
        exit()
