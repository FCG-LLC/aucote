"""
Provides classes for executing and fetching output from system commands.

"""
import tempfile
import logging as log
import subprocess

from aucote_cfg import cfg
from tools.common.parsers import Parser


class Command(object):
    """

    Base file for all classes that call a command (create process) using command line arguments.

    """

    #to be set by child classes.
    COMMON_ARGS = None
    NAME = None
    parser = Parser

    def call(self, args=None):
        """
        Calls system command and return parsed output or standard error output

        Args:
            args (list):

        Returns:

        """
        if args is None:
            args = []

        all_args = [cfg.get('tools.%s.cmd' % self.NAME)]
        all_args.extend(self.COMMON_ARGS)
        all_args.extend(args)
        log.debug('Executing: %s', ' '.join(all_args))
        with tempfile.TemporaryFile() as temp_file:
            temp_file.truncate()
            try:
                stdout = subprocess.check_output(all_args, stderr=temp_file).decode('utf-8')
                return self.parser.parse(stdout)
            except subprocess.CalledProcessError as exception:
                temp_file.seek(0)
                stderr_lines = [line.decode() for line in temp_file.readlines()]
                self.handle_exception(exception, stderr_lines)

    @classmethod
    def handle_exception(cls, exception, stderr):
        log.warning("Command '%s' Failed and returns %i:\n\n%s", exception.cmd, exception.returncode,
                    "".join(stderr))
        raise exception
