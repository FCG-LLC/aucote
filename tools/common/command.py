"""
Provides classes for executing and fetching output from system commands.

"""
import tempfile
import logging as log
import subprocess

from tornado import gen
from tornado import process

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
                return self.parser.parse(subprocess.check_output(all_args, stderr=temp_file).decode('utf-8'))
            except subprocess.CalledProcessError as exception:
                temp_file.seek(0)
                log.warning("Command '%s' Failed:\n\n%s", " ".join(all_args),
                            "".join([line.decode() for line in temp_file.readlines()]))
                raise exception

    @gen.coroutine
    def async_call(self, args=None):
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

        task = process.Subprocess(all_args, stderr=process.Subprocess.STREAM, stdout=process.Subprocess.STREAM)
        try:
            yield task.wait_for_exit()
            result = yield task.stdout.read_until_close()
            return self.parser.parse(result.decode('utf-8'))
        except subprocess.CalledProcessError as exception:
            stdout_result = yield task.stdout.read_until_close()
            stderr_result = yield task.stderr.read_until_close()
            log.warning("Command '%s' Failed:\nSTDOUT:\n%s\nSTDERR:\n%s", " ".join(all_args), stdout_result, stderr_result)
            raise exception
