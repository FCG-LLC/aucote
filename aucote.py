"""
This is executable file of aucote project.
"""

import argparse
import logging as log
import os
import re
from os import chdir
from os.path import dirname, realpath
import sys
import fcntl

import signal
from typing import Optional
from unittest.mock import MagicMock

from functools import partial
from tornado import gen
from tornado.gen import multi
from tornado.ioloop import IOLoop

from fixtures.exploits import Exploits
from scans.executor_config import EXECUTOR_CONFIG
from scans.tcp_scanner import TCPScanner
from scans.tools_scanner import ToolsScanner
from scans.udp_scanner import UDPScanner
from structs import TaskManagerType
from threads.storage_thread import StorageThread
from threads.tftp_thread import TFTPThread
from utils.async_task_manager import AsyncTaskManager
from utils.exceptions import NmapUnsupported, TopdisConnectionException
from utils.storage import Storage
from utils.kudu_queue import KuduQueue
from utils.topdis import Topdis
from utils.web_server import WebServer
from database.serializer import Serializer
from aucote_cfg import cfg, load as cfg_load
from tornado.platform.asyncio import AsyncIOMainLoop
import asyncio

VERSION = (0, 1, 0)
APP_NAME = 'Automated Compliance Tests'


# ============== main app ==============
async def main():
    """
    Main function of aucote project
    Returns:

    """
    print("%s, version: %s.%s.%s" % ((APP_NAME,) + VERSION))

    # parse arguments
    parser = argparse.ArgumentParser(description='Tests compliance of devices.')
    parser.add_argument("--cfg", help="config file path")
    parser.add_argument('cmd', help="aucote command", type=str, default='service',
                        choices=['scan', 'service'],
                        nargs='?')
    parser.add_argument("--syncdb", action="store_true", help="Synchronize database")
    args = parser.parse_args()

    # read configuration
    await cfg_load(args.cfg)

    log.info("%s, version: %s.%s.%s", APP_NAME, *VERSION)

    try:
        lock = open(cfg['pid_file'], 'w')
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        log.error("There is another Aucote instance running already")
        sys.exit(1)

    exploit_filename = cfg['fixtures.exploits.filename']
    try:
        exploits = Exploits.read(file_name=exploit_filename)
    except NmapUnsupported:
        log.exception("Cofiguration seems to be invalid. Check ports and services or contact with collective-sense")
        exit(1)

    def get_kuduworker():
        """
        Get kudu worker if enable, mock otherwise

        Returns:
            KuduQueue|MagicMock

        """
        if cfg['kuduworker.enable']:
            return KuduQueue(cfg['kuduworker.queue.address'])
        return MagicMock()  # used for local testing

    with get_kuduworker() as kudu_queue:
        aucote = Aucote(exploits=exploits, kudu_queue=kudu_queue, tools_config=EXECUTOR_CONFIG)

        if args.syncdb:
            log.info('Pushing %s exploits to the database', len(exploits))
            aucote.run_syncdb()

        if args.cmd == 'scan':
            await aucote.run_scan(as_service=False)
            IOLoop.current().stop()
        elif args.cmd == 'service':
            while True:
                await aucote.run_scan()
                cfg.reload(cfg['config_filename'])


# =============== functions ==============


class Aucote(object):
    """
    Main aucote class. It Provides run functions (service, single instance, sync db)
    """

    SCAN_CONTROL_START = re.compile(r'portdetection\.(?P<scan_name>[a-zA-Z0-9_]+)\.control\.start')
    SCAN_CONTROL_STOP = re.compile(r'portdetection\.(?P<scan_name>[a-zA-Z0-9_]+)\.control\.stop')
    SCAN_CONTROL_RESUME = re.compile(r'portdetection\.(?P<scan_name>[a-zA-Z0-9_]+)\.control\.resume')

    def __init__(self, exploits, kudu_queue, tools_config):
        self.exploits = exploits
        self._kudu_queue = kudu_queue
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGHUP, self.graceful_stop)
        self.load_tools(tools_config)

        self._storage = Storage(conn_string=cfg['storage.db'], nodes_limit=cfg['storage.max_nodes_query'])

        self.ioloop = IOLoop.current()
        self.topdis = Topdis(cfg['topdis.api.host'], cfg['topdis.api.port'], cfg['topdis.api.base'])

        self.async_task_managers = {
            TaskManagerType.SCANNER: AsyncTaskManager.instance(name=TaskManagerType.SCANNER.value,
                                                               parallel_tasks=10),
            TaskManagerType.REGULAR: AsyncTaskManager.instance(name=TaskManagerType.REGULAR.value,
                                                               parallel_tasks=cfg['service.scans.parallel_tasks']),
            TaskManagerType.QUICK: AsyncTaskManager.instance(name=TaskManagerType.QUICK.value, parallel_tasks=30)
        }

        self.web_server = WebServer(self, cfg['service.api.v1.host'], cfg['service.api.v1.port'],
                                    path=cfg['service.api.path'])
        self._tftp_thread = TFTPThread(cfg['tftp.host'], cfg['tftp.port'], timeout=cfg['tftp.timeout'],
                                       min_port=cfg['tftp.min_port'], max_port=cfg['tftp.max_port'])

        self._storage_thread = StorageThread(storage=self._storage)
        self.scanners = []

        if cfg.toucan:
            for task_manager in self.async_task_managers.values():
                cfg.toucan_monitor.register_toucan_key(key='throttling.rate', add_prefix=False, default=1,
                                                       callback=task_manager.change_throttling_toucan)

    @property
    def kudu_queue(self):
        """
        Returns:
            KuduQueue

        """
        return self._kudu_queue

    @property
    def tftp_server(self):
        return self._tftp_thread

    def _control_scanner(self, scanner):
        if cfg.toucan:
            start_key = 'portdetection.{}.control.start'.format(scanner.NAME)
            stop_key = 'portdetection.{}.control.stop'.format(scanner.NAME)
            resume_key = 'portdetection.{}.control.resume'.format(scanner.NAME)
            cfg.toucan_monitor.register_toucan_key(start_key, callback=self.start_scan, default=False, add_prefix=True)
            cfg.toucan_monitor.register_toucan_key(stop_key, callback=self.stop_scan, default=False, add_prefix=True)
            cfg.toucan_monitor.register_toucan_key(resume_key, callback=self.resume_scan, default=False, add_prefix=True)

    async def run_scan(self, as_service=True):
        """
        Start scanning ports.

        Returns: None

        """
        scan_task_manager = self.async_task_managers[TaskManagerType.SCANNER]
        try:
            with self._storage_thread, self._tftp_thread:
                scan_task_manager.clear()
                self._storage.init_schema()
                async with self.web_server:
                    self.ioloop.add_callback(self.web_server.run)

                    tcp_host = cfg['tcpportscan.host']
                    tcp_port = int(cfg['tcpportscan.port'])

                    self.scanners = [
                        TCPScanner(host=tcp_host, port=tcp_port, aucote=self, as_service=as_service),
                        UDPScanner(aucote=self, as_service=as_service)
                    ]

                    if as_service:
                        for scanner in self.scanners:
                            scan_task_manager.add_crontab_task(scanner, scanner._scan_cron)
                            self._control_scanner(scanner)

                        for scanner_name in cfg['portdetection.security_scans'].cfg:
                            scanner = ToolsScanner(aucote=self, name=scanner_name)
                            self.scanners.append(scanner)
                            scan_task_manager.add_crontab_task(scanner, scanner._scan_cron, event='tools')
                            self._control_scanner(scanner)

                        self._start_all_task_managers()
                    else:
                        self._start_all_task_managers()
                        await gen.multi(scanner() for scanner in self.scanners)
                        self._stop_all_task_managers()

                    await self._wait_on_task_managers()

            log.info("Closing loop")

        except TopdisConnectionException:
            log.exception("Exception while connecting to Topdis")

    def _start_all_task_managers(self):
        for task_manager in self.async_task_managers.values():
            task_manager.start()

    def _stop_all_task_managers(self):
        for task_manager in self.async_task_managers.values():
            task_manager.stop()

    async def _wait_on_task_managers(self):
        await multi([task_manager.shutdown_condition.wait() for task_manager in self.async_task_managers.values()])

    def run_syncdb(self):
        """
        Synchronize local exploits database with Kudu

        Returns:
            None

        """
        serializer = Serializer()
        for exploit in self.exploits:
            self.kudu_queue.send_msg(serializer.serialize_exploit(exploit))

    def add_async_task(self, task, manager: TaskManagerType = TaskManagerType.REGULAR):
        """
        Add async task for executing

        Args:
            task (Task):
            manager: Name of task manager (regular as default)

        Returns:
            None

        """
        log.debug('Added task: %s', task)
        self.async_task_managers[manager].add_task(task)

    def signal_handler(self, sig, frame):
        """
        Handling signals from operating system. Exits applications (kills all threads).

        Args:
            sig:
            frame:

        Returns:

        """
        log.error("Received signal %s at frame %s. Exiting.", sig, frame)
        self.kill()

    @property
    def unfinished_tasks(self):
        """
        Get number of unfinished tasks.

        Returns:
            int

        """
        return sum(task_manager.unfinished_tasks for task_manager in self.async_task_managers.values())

    def load_tools(self, config):
        """
        Load tools, if tools require config

        Returns:
            None

        """
        for name, app in config['apps'].items():
            if app.get('loader', None):
                log.info('Loading %s', name)
                app['loader'](app, self.exploits)

    def graceful_stop(self, sig, frame):
        """
        Responsible for stopping the threads in graceful way.

        Returns:
            None

        """
        log.debug("Stop gracefuly")
        self.ioloop.add_callback_from_signal(self._graceful_stop)

    async def _graceful_stop(self):
        for task_manager in self.async_task_managers.values():
            await task_manager.stop()

    @classmethod
    def kill(cls):
        """
        Kill aucote by sending signal

        Returns:
            None

        """
        os._exit(1)

    @property
    def storage(self):
        """
        Aucote's storage

        Returns:
            Storage

        """
        return self._storage

    def _get_scan_name(self, regex, key):
        match = regex.match(key)
        if match is None:
            raise KeyError('Cannot find scan_name for key {}'.format(key))

        return match.groupdict()['scan_name']

    def start_scan(self, key, value, scan_name=None):
        """
        Start scan with given name (scan_name) as soon as possible

        """
        scan_name = self._get_scan_name(self.SCAN_CONTROL_START, key) if scan_name is None else scan_name

        if value is True:
            log.debug('Starting %s basing on Toucan request', scan_name)
            cfg.toucan.put(key, False)
            self.ioloop.add_callback(partial(
                self.async_task_managers[TaskManagerType.SCANNER].cron_task(scan_name), skip_cron=True))

    def stop_scan(self, key, value, scan_name=None):
        """
        Stop scan with given name (scan_name)

        """
        scan_name = self._get_scan_name(self.SCAN_CONTROL_STOP, key) if scan_name is None else scan_name

        if value is True:
            log.debug('Stopping %s basing on Toucan request', scan_name)
            cfg.toucan.put(key, False)
            self.ioloop.add_callback(self.async_task_managers[TaskManagerType.SCANNER].cron_task(scan_name).func.stop)

    def resume_scan(self, key, value, scan_name: Optional[str] = None):
        scan_name = self._get_scan_name(self.SCAN_CONTROL_RESUME, key) if scan_name is None else scan_name

        if value is True:
            log.debug('Resuming %s basing on Toucan request', scan_name)
            cfg.toucan.put(key, False)
            self.ioloop.add_callback(partial(
                self.async_task_managers[TaskManagerType.SCANNER].cron_task(scan_name), skip_cron=True, resume=True))


# =================== start app =================

if __name__ == "__main__":  # pragma: no cover
    chdir(dirname(realpath(__file__)))
    AsyncIOMainLoop().install()
    IOLoop.current().add_callback(main)
    asyncio.get_event_loop().run_forever()
