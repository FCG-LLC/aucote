"""
Provides classes for executing and fetching output from system commands.

"""
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
        cmd = ' '.join(all_args),
        log.debug('Executing: %s', cmd)

        proc = subprocess.run(all_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr

        if return_code != 0:
            log.warning("Command '%s' failed wit exit code: %s", cmd, return_code)
            log.debug("Command '%s':\nSTDOUT:\n%s\nSTDERR:\n%s", cmd, stdout, stderr)
            raise subprocess.CalledProcessError(return_code, cmd)

        return self.parser.parse(stdout.decode('utf-8'), stderr.decode('utf-8'))

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
        cmd = ' '.join(all_args),
        log.debug('Executing: %s', cmd)

        task = process.Subprocess(all_args, stderr=process.Subprocess.STREAM, stdout=process.Subprocess.STREAM)

        return_code, stdout, stderr = yield gen.multi([task.wait_for_exit(raise_error=False),
                                                       task.stdout.read_until_close(),
                                                       task.stderr.read_until_close()])

        if return_code != 0:
            log.warning("Command '%s' failed wit exit code: %s", cmd, return_code)
            log.debug("Command '%s':\nSTDOUT:\n%s\nSTDERR:\n%s", cmd, stdout, stderr)
            raise subprocess.CalledProcessError(return_code, cmd)

        return self.parser.parse(stdout.decode('utf-8'), stderr.decode('utf-8'))
