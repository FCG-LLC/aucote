"""
Provides classes for executing and fetching output from system commands.

"""
import logging as log
import subprocess
from asyncio import CancelledError
from datetime import timedelta

from tornado import gen
from tornado import process
from tornado.platform.asyncio import to_asyncio_future

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
            return_code, stdout, stderr = await to_asyncio_future(coroutine)
        else:
            try:
                return_code, stdout, stderr = await to_asyncio_future(gen.with_timeout(timedelta(seconds=timeout),
                                                                                       coroutine))
            except (gen.TimeoutError, CancelledError) as exception:
                if isinstance(exception, gen.TimeoutError):
                    log.exception("Command %s timed out after %s while executing %s", self.NAME, timeout, cmd)
                elif isinstance(exception, CancelledError):
                    log.warning("Command %s cancelled by task manager during executing %s", self.NAME, cmd)
                task.proc.kill()
                raise exception

        if return_code != 0:
            log.warning("Command '%s' failed wit exit code: %s", cmd, return_code)
            log.debug("Command '%s':\nSTDOUT:\n%s\nSTDERR:\n%s", cmd, stdout, stderr)
            if self.RAISE_ERROR:
                raise subprocess.CalledProcessError(return_code, cmd)

        return self.parser.parse(stdout.decode('utf-8'), stderr.decode('utf-8'))
