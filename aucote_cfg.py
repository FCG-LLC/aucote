'''
This module provides default configuration and the global instance for the utils.Config class.
'''
import os.path as path
from sys import stderr

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
    'tools':{
        'nmap':{
            'cmd': 'nmap',
            'enable': True,
            'period': '1d',
            'disable_scripts': []
        },
        'masscan': {
            'cmd': 'masscan',
            'args': []
        },
        'hydra': {
            'cmd': 'hydra',
            'loginfile': 'static/logins.hydra.txt',
            'passwordfile': 'static/passwords.hydra.txt',
            'enable': True,
            'disable_services': ['vnc', 'http', 'https'],
            'period': '1d'
        },
        'skipfish': {
            'cmd': 'skipfish',
            'enable': True,
            'limit': '0:10:00',
            'threads': 5,
            'tmp_directory': '/tmp',
            'period': '1d'
        },
        'aucote-http-headers': {
            'enable': True,
            'period': ''
        },
        'common': {
            'rate': 80
        }
    },
    'service': {
        'scans': {
            'useragent': None,
            'threads': 10,
            'ports': '0-65535,U:0-65535',
            'network_scan_rate': 1000,
            'port_scan_rate': 1000,
            'port_period': '5m',
            'node_period': '1m',
            'storage': 'storage.sqlite3',
            'physical': True,
            'broadcast': True
        },
        "api": {
            'v1': {
                'host': '0.0.0.0',
                'port': 1235
            }
        }
    },
    'pid_file': 'aucote.pid'
}

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
