"""
This is executable file of aucote project.
"""

import argparse
import logging as log
import os
from os import chdir
from os.path import dirname, realpath
import sys
import fcntl

import signal
from unittest.mock import MagicMock

from functools import partial
from tornado import gen
from tornado.ioloop import IOLoop

from fixtures.exploits import Exploits
from scans.executor_config import EXECUTOR_CONFIG
from scans.tcp_scanner import TCPScanner
from scans.tools_scanner import ToolsScanner
from scans.udp_scanner import UDPScanner
from utils.async_task_manager import AsyncTaskManager, ThrottlingConsumer
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
                        choices=['scan', 'service', 'syncdb'],
                        nargs='?')
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
        if cfg['storage.fresh_start']:
            try:
                os.remove(cfg['storage.path'])
            except FileNotFoundError:
                pass

        aucote = Aucote(exploits=exploits, kudu_queue=kudu_queue, tools_config=EXECUTOR_CONFIG)

        if args.cmd == 'scan':
            await aucote.run_scan(as_service=False)
            IOLoop.current().stop()
        elif args.cmd == 'service':
            while True:
                await aucote.run_scan()
                cfg.reload(cfg['config_filename'])
        elif args.cmd == 'syncdb':
            aucote.run_syncdb()


# =============== functions ==============


class Aucote(object):
    """
    Main aucote class. It Provides run functions (service, single instance, sync db)
    """

    def __init__(self, exploits, kudu_queue, tools_config):
        self.exploits = exploits
        self._kudu_queue = kudu_queue
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGHUP, self.graceful_stop)
        self.load_tools(tools_config)

        self._storage = Storage(filename=cfg['storage.path'], nodes_limit=cfg['storage.max_nodes_query'])

        self.ioloop = IOLoop.current()
        self.topdis = Topdis(cfg['topdis.api.host'], cfg['topdis.api.port'])

        self.async_task_manager = AsyncTaskManager.instance(parallel_tasks=cfg['service.scans.parallel_tasks'])
        self._throttling_consumer = ThrottlingConsumer(manager=self.async_task_manager)
        self.ioloop.add_callback(partial(cfg.add_rabbit_consumer, self._throttling_consumer))
        self.ioloop.add_callback(self._throttling_consumer.consume)

        self.web_server = WebServer(self, cfg['service.api.v1.host'], cfg['service.api.v1.port'])
        self.scanners = []

    @property
    def kudu_queue(self):
        """
        Returns:
            KuduQueue

        """
        return self._kudu_queue

    async def run_scan(self, as_service=True):
        """
        Start scanning ports.

        Returns: None

        """
        try:
            self.async_task_manager.clear()
            self._storage.connect()
            self._storage.init_schema()
            self.ioloop.add_callback(self.web_server.run)

            tcp_host = cfg['tcpportscan.host'].cfg
            tcp_port = cfg['tcpportscan.port'].cfg

            self.scanners = [
                TCPScanner(host=tcp_host, port=tcp_port, aucote=self, as_service=as_service),
                UDPScanner(aucote=self, as_service=as_service)
            ]

            if as_service:
                for scanner in self.scanners:
                    self.async_task_manager.add_crontab_task(scanner, scanner._scan_cron)

                for scanner_name in cfg['portdetection.security_scans'].cfg:
                    scanner = ToolsScanner(aucote=self, name=scanner_name)
                    self.scanners.append(scanner)
                    self.async_task_manager.add_crontab_task(scanner, scanner._scan_cron, event='tools')

                self.async_task_manager.start()
            else:
                self.async_task_manager.start()
                await gen.multi(scanner() for scanner in self.scanners)
                self.async_task_manager.stop()

            await self.async_task_manager.shutdown_condition.wait()

            self.web_server.stop()
            self._storage.close()

            log.info("Closing loop")

        except TopdisConnectionException:
            log.exception("Exception while connecting to Topdis")

    def run_syncdb(self):
        """
        Synchronize local exploits database with Kudu

        Returns:
            None

        """
        serializer = Serializer()
        for exploit in self.exploits:
            self.kudu_queue.send_msg(serializer.serialize_exploit(exploit))

    def add_async_task(self, task):
        """
        Add async task for executing

        Args:
            task (Task):

        Returns:
            None

        """
        log.debug('Added task: %s', task)
        self.async_task_manager.add_task(task)

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
        return self.async_task_manager.unfinished_tasks

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
        await self.async_task_manager.stop()

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

# =================== start app =================

if __name__ == "__main__":  # pragma: no cover
    chdir(dirname(realpath(__file__)))
    AsyncIOMainLoop().install()
    IOLoop.current().add_callback(main)
    asyncio.get_event_loop().run_forever()
