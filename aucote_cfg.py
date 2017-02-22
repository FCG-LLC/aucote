'''
This module provides default configuration and the global instance for the utils.Config class.
'''
import os.path as path
from sys import stderr
import utils.log as log_cfg

import exrex

from utils import Config

#default values
_DEFAULT = {
    'logging':{
        'file': lambda: path.join(path.dirname(__file__), 'aucote.log'),
        'level': 'info',
        'max_file_size': 10*1024*1024,
        'max_files': 5,
        'format': '%(levelname)s %(asctime)s %(threadName)s: %(message)s'
    },
    'fixtures': {
        'exploits': {
            'filename': 'fixtures/exploits/exploits.csv'
        }
    },
    'database': {
        'migration':{
            'path': lambda: path.join(path.dirname(__file__), 'migrations'),
        },
        'credentials':{
            'port': 5432
        }
    },
    'topdis':{
        'api': {
            'host': 'localhost',
            'port': 1234
        }
    },
    'pid_file': 'aucote.pid',
    'default_config': 'aucote_cfg_default.yaml'
}

_TOUCAN_KEYS = [
    exrex.generate('service\.scans\.(useragent|ports|rate|port_period|node_period|physical|broadcast)'),
    exrex.generate('tools\.(nmap|aucote-http-headers)\.(enable)'),
]

#global cfg
cfg = Config(_DEFAULT)


def load(file_name=None):
    '''
    Initializes this module.
    Needs to be called before other functions are used.
    '''

    if file_name is None:
        #by default search for "confg.yaml" in application dir
        file_name = path.join(path.dirname(__file__), 'aucote_cfg.yaml')

    file_name = path.abspath(file_name)
    #at this point logs do not work, print info to stdout
    print("Reading configuration from file:", file_name)
    try:
        cfg.load(file_name, _DEFAULT)
    except Exception:
        stderr.write("Cannot load configuration file {0}".format(file_name))
        exit()

    default_config_filename = cfg.get('default_config')

    try:
        cfg.load(default_config_filename, cfg._cfg)
    except Exception:
        stderr.write("Cannot load configuration file {0}".format(default_config_filename))
        exit()


    log_cfg.config(cfg.get('logging'))

    cfg.load_toucan(_TOUCAN_KEYS)
