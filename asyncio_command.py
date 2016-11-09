import asyncio.subprocess
import os
from asyncio import wait_for, futures


@asyncio.coroutine
def _call_asyncio(command, arguments):
    instance = asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE,
                                            stderr=asyncio.subprocess.PIPE)

    process = yield from instance
    stdout_data = b""
    stderr_data = b""

    iterator = iter(arguments)
    current_arg = next(iterator)

    while True:
        try:
            os.kill(process.pid, 0)
        except ProcessLookupError:
            yield from process.wait()
            return stdout_data

        yield from wait_for(instance, None)

        try:
            data = yield from wait_for(process.stdout.read(4096), 0.5)

            if data:
                stdout_data += data
        except futures.TimeoutError:
            pass

        try:
            data = yield from wait_for(process.stderr.read(4096), 0.5)
            if data:
                stderr_data += data
        except futures.TimeoutError:
            pass

        if current_arg and stdout_data.endswith(current_arg[0]):
            process.stdin.write(current_arg[1])
            stdout_data += current_arg[1]
            yield from process.stdin.drain()
            try:
                current_arg = next(iterator)
            except StopIteration:
                current_arg = None


loop = asyncio.get_event_loop()

all_args = ['perl', '/home/wolodija/Projects/cisco-global-exploiter/cge.pl', '127.0.0.1', '9']
arguments = [
    (b'Input packets size : ', b'50\n'),
    (b'Please enter a server\'s open port : ', b'22\n')
]

date = loop.run_until_complete(_call_asyncio(all_args, arguments))
print("Current date: %s" % date.decode())
loop.close()

