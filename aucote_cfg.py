'''
This module provides default configuration and the global instance for the utils.Config class.
'''
import os.path as path
from sys import stderr

import yaml

import utils.log as log_cfg
from utils import Config

# default values
from utils.toucan import Toucan

_DEFAULT = {
    'logging': {
        'file': lambda: path.join(path.dirname(__file__), 'aucote.log'),
        'level': 'info',
        'max_file_size': 10 * 1024 * 1024,
        'max_files': 5,
        'format': '%(levelname)s %(asctime)s %(threadName)s: %(message)s'
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
        }
    },
    'toucan': {
        'enable': True,
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


def start_toucan(default_config):
    """
    Initialize Toucan

    Args:
        default_config:

    Returns:
        None

    """
    Toucan.min_retry_time = cfg['toucan.min_retry_time']
    Toucan.max_retry_time = cfg['toucan.max_retry_time']
    Toucan.max_retry_count = cfg['toucan.max_retry_count']

    cfg.toucan = Toucan(api=cfg['toucan.api'])

    with open(default_config, "r") as file:
        config = yaml.load(file)

    cfg.toucan.push_config(config, overwrite=False)


def load(file_name=None):
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

    log_cfg.config(cfg['logging'])

    default_config_filename = cfg['default_config']

    if cfg.get('toucan.enable'):
        start_toucan(default_config_filename)
    else:
        try:
            cfg.load(default_config_filename, cfg.cfg)
        except Exception:
            stderr.write("Cannot load configuration file {0}".format(default_config_filename))
            exit()
