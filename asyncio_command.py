import asyncio.subprocess
import sys
import time
import os
from asyncio import wait_for

all_args = ['nmap', '--script', 'banner', '-p', '0-65535', '127.0.0.1']


@asyncio.coroutine
def get_date():
    create = asyncio.create_subprocess_exec(*all_args, stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE,
                                            stderr=asyncio.subprocess.PIPE)
    proc = yield from create
    stdout_data = b""
    stderr_data = b""

    while True:
        try:
            os.kill(proc.pid, 0)
        except ProcessLookupError:
            return stdout_data

        yield from wait_for(create, None)
        data = yield from proc.stdout.read(4096)
        if data:
            stdout_data += data

        data = yield from proc.stderr.read(4096)
        if data:
            stderr_data += data

        if data:
            print(data)
            proc.stdin.write(b"\n")
            yield from proc.stdin.drain()
            time.sleep(5)

    # Wait for the subprocess exit
    # yield from proc.wait()
    # return data

if sys.platform == "win32":
    loop = asyncio.ProactorEventLoop()
    asyncio.set_event_loop(loop)
else:
    loop = asyncio.get_event_loop()

date = loop.run_until_complete(get_date())
print("Current date: %s" % date)
loop.close()

