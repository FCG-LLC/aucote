'''
This module provides default configuration and the global instance for the utils.Config class.
'''
import os.path as path
from utils import Config

#default values
_DEFAULT = {
    'logging':{
        'file': lambda: path.join(path.dirname(__file__), 'aucote.log'),
        'level': 'info'
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
            'cmd': 'nmap'
        },
        'masscan': {
            'cmd': 'masscan',
            'rate': 1000,
            'ports': '0-65535,U:0-65535'
        }
    },
    'service': {
        'scans': {
            'period': '12h',
            'threads': 10,
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
def load(file_name):
    '''
    Initializes this module.
    Needs to be called before other functions are used.
    '''

    if file_name is None:
        #by default search for "confg.yaml" in application dir
        file_name = path.join(path.dirname(__file__), 'aucote_cfg.yaml')
    #at this point logs do not work, print info to stdout
    print("Reading configuration from file:", file_name)
    cfg.load(file_name)