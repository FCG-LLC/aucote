"""
Provides classes for executing and fetching output from system commands.

"""
import asyncio
import os
import tempfile
import logging as log
import subprocess

from aucote_cfg import cfg
from tools.common import Command


class AsyncCommand(Command):
    """

    Base file for all classes that call a command asynchronously (create process) using command line arguments.

    """

    def call(self, args=None):
        """
        Calls system command and return parsed output or standard error output

        Args:
            args (list):

        Returns:

        """
        stdin = args[1] or []
        args = args[0] or []

        all_args = [cfg.get('tools.%s.cmd' % self.NAME)]
        all_args.extend(self.COMMON_ARGS)
        all_args.extend(args)
        log.debug('Executing: %s', ' '.join(all_args))

        with tempfile.TemporaryFile() as temp_file:
            temp_file.truncate()
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop = asyncio.get_event_loop()
                print("lets wait")
                data = loop.run_until_complete(self._call_asyncio(all_args, stdin))
                print(data)
                return self.parser.parse(data.decode('utf-8'))
            except subprocess.CalledProcessError as exception:
                temp_file.seek(0)
                stderr_lines = [line.decode() for line in temp_file.readlines()]
                log.warning("Command '%s' Failed and returns %i:\n\n%s", " ".join(all_args), exception.returncode,
                            "".join(stderr_lines))
                self.handle_exception(exception, stderr_lines)

    @classmethod
    def handle_exception(self, exception, stderr):
        raise exception

    @asyncio.coroutine
    def _call_asyncio(self, command, arguments):
        command = ['ls']
        instance = asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                                                  stdin=asyncio.subprocess.PIPE,
                                                  stderr=asyncio.subprocess.PIPE)

        process = yield from instance
        stdout_data = b""
        stderr_data = b""

        iterator = iter(arguments)
        try:
            current_arg = next(iterator)
        except StopIteration:
            current_arg = None

        while True:
            try:
                os.kill(process.pid, 0)
            except ProcessLookupError:
                yield from process.wait()
                return stdout_data

            yield from asyncio.wait_for(instance, None)

            try:
                data = yield from asyncio.wait_for(process.stdout.read(4096), 0.5)

                if data:
                    stdout_data += data
            except asyncio.futures.TimeoutError:
                pass

            try:
                data = yield from asyncio.wait_for(process.stderr.read(4096), 0.5)
                if data:
                    stderr_data += data
            except asyncio.futures.TimeoutError:
                pass

            if current_arg and stdout_data.endswith(current_arg[0]):
                process.stdin.write(current_arg[1])
                stdout_data += current_arg[1]
                yield from process.stdin.drain()
                try:
                    current_arg = next(iterator)
                except StopIteration:
                    current_arg = None
