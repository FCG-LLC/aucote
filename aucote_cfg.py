'''
This module provides default configuration and the global instance for the utils.Config class.
'''
import os.path as path
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
            'enable': True
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
        },
        'skipfish': {
            'cmd': 'skipfish',
            'enable': True,
            'limit': '0:10:00',
            'wordlist': 'static/minimal.wl'
        }
    },
    'service': {
        'scans': {
            'period': '12h',
            'threads': 10,
            'ports': '0-65535,U:0-65535',
            'rate': 1000,
        },
        "api":{
            'v1': {
                'host': '0.0.0.0',
                'port': 1235
            }
        }
    }
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
    #at this point logs do not work, print info to stdout
    print("Reading configuration from file:", file_name)
    cfg.load(file_name, _DEFAULT)
