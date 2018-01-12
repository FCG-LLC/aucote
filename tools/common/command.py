"""
Provides classes for executing and fetching output from system commands.

"""
import logging as log
import subprocess
from datetime import timedelta

import threading
from tornado import gen
from tornado import process

from aucote_cfg import cfg
from tools.common.parsers import Parser
from utils.exceptions import NonXMLOutputException


class Command(object):
    """
    Base file for all classes that call a command (create process) using command line arguments.

    """

    #to be set by child classes.
    COMMON_ARGS = None
    RAISE_ERROR = True
    NAME = None
    CMD = None
    parser = Parser()

    def call(self, args=None, timeout=None):
        """
        Calls system command and return parsed output or standard error output

        """
        if args is None:
            args = []

        all_args = [self.CMD if self.CMD is not None else cfg['tools.%s.cmd' % self.NAME]]
        all_args.extend(self.COMMON_ARGS)
        all_args.extend(args)
        cmd = ' '.join(all_args),
        log.debug('Executing: %s', cmd)

        proc = subprocess.run(all_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr

        if return_code != 0:
            log.warning("Command '%s' failed wit exit code: %s", cmd, return_code)
            log.debug("Command '%s':\nSTDOUT:\n%s\nSTDERR:\n%s", cmd, stdout, stderr)
            if self.RAISE_ERROR:
                raise subprocess.CalledProcessError(return_code, cmd)

        return self.parser.parse(stdout.decode('utf-8'), stderr.decode('utf-8'))

    async def async_call(self, args=None, timeout=None):
        """
        Calls system command and return parsed output or standard error output

        """
        if args is None:
            args = []

        if threading.main_thread().ident != threading.get_ident():
            return self.call(args=args, timeout=timeout)

        all_args = [self.CMD if self.CMD is not None else cfg['tools.%s.cmd' % self.NAME]]
        all_args.extend(self.COMMON_ARGS)
        all_args.extend(args)
        cmd = ' '.join(all_args),
        log.debug('Executing: %s', cmd)

        task = process.Subprocess(all_args, stderr=process.Subprocess.STREAM, stdout=process.Subprocess.STREAM)

        coroutine = gen.multi([task.wait_for_exit(raise_error=False),
                               task.stdout.read_until_close(),
                               task.stderr.read_until_close()])

        if not timeout:
            return_code, stdout, stderr = await coroutine
        else:
            try:
                return_code, stdout, stderr = await gen.with_timeout(timedelta(seconds=timeout), coroutine)
            except gen.TimeoutError as exception:
                log.exception("Command %s timed out after %s while executing %s", self.NAME, timeout, cmd)
                task.proc.kill()
                raise exception

        if return_code != 0:
            log.warning("Command '%s' failed wit exit code: %s", cmd, return_code)
            log.debug("Command '%s':\nSTDOUT:\n%s\nSTDERR:\n%s", cmd, stdout, stderr)
            if self.RAISE_ERROR:
                raise subprocess.CalledProcessError(return_code, cmd)

        return self.parser.parse(stdout.decode('utf-8'), stderr.decode('utf-8'))
