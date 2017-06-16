"""
Main file of testssl integration

"""
import tempfile

from tools.common import Command
from tools.ssl.parsers import SSLParser


class SSLBase(Command):
    """
    Extends command and provide execution schema

    """
    NAME = 'testssl'
    COMMON_ARGS = ['--warnings',  'batch']
    RAISE_ERROR = False
    parser = None

    def __init__(self):
        temporary_file = tempfile.NamedTemporaryFile('r+')
        self.COMMON_ARGS.extend(['--jsonfile', temporary_file.name, '--append'])
        self.parser = SSLParser(temporary_file)
        super(SSLBase, self).__init__()
