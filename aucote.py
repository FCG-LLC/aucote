"""
This is executable file of aucote project.
"""

import argparse
import logging as log
import threading
import os
from os import chdir
from os.path import dirname, realpath
import sys
import fcntl

import signal

from fixtures.exploits import Exploits
from scans.executor_config import EXECUTOR_CONFIG
from scans.scan_task import ScanTask
from scans.task_mapper import TaskMapper
import utils.log as log_cfg
from threads.storage_thread import StorageThread
from utils.exceptions import NmapUnsupported, TopdisConnectionException
from utils.threads import ThreadPool
from utils.kudu_queue import KuduQueue
from utils.watchdog_task import WatchdogTask
from database.serializer import Serializer
from aucote_cfg import cfg, load as cfg_load

#constants

VERSION = (0, 1, 0)
APP_NAME = 'Automated Compliance Tests'


# ============== main app ==============
def main():
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
    cfg_load(args.cfg)

    log_cfg.config(cfg.get('logging'))
    log.info("%s, version: %s.%s.%s", APP_NAME, *VERSION)

    try:
        lock = open(cfg.get('pid_file'), 'w')
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        log.error("There is another Aucote instance running already")
        sys.exit(1)

    exploit_filename = cfg.get('fixtures.exploits.filename')
    try:
        exploits = Exploits.read(file_name=exploit_filename)
    except NmapUnsupported:
        log.exception("Cofiguration seems to be invalid. Check ports and services or contact with collective-sense")
        exit(1)

    with KuduQueue(cfg.get('kuduworker.queue.address')) as kudu_queue:

        try:
            os.remove(cfg.get('service.scans.storage'))
        except FileNotFoundError:
            pass

        aucote = Aucote(exploits=exploits, kudu_queue=kudu_queue, tools_config=EXECUTOR_CONFIG)

        if args.cmd == 'scan':
            aucote.run_scan(as_service=False)
        elif args.cmd == 'service':
            while True:
                aucote.run_scan()
                cfg.reload(cfg.get('config_filename'))
        elif args.cmd == 'syncdb':
            aucote.run_syncdb()


# =============== functions ==============


class Aucote(object):
    """
    Main aucote class. It Provides run functions (service, single instance, sync db)
    """

    def __init__(self, exploits, kudu_queue, tools_config):
        self.exploits = exploits
        self._thread_pool = ThreadPool(cfg.get('service.scans.threads'))
        self._kudu_queue = kudu_queue
        self._storage = None
        self.task_mapper = TaskMapper(self)
        self.filename = cfg.get('service.scans.storage')
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        self.lock = threading.Lock()
        self.load_tools(tools_config)
        self.scan_task = None
        self.watch_task = None
        self.storage_thread = None

    @property
    def kudu_queue(self):
        """
        Returns:
            KuduQueue

        """
        return self._kudu_queue

    @property
    def storage(self):
        """
        Returns:
            Storage

        """
        return self._storage

    @storage.setter
    def storage(self, storage):
        if not self._storage or storage is None:
            self._storage = storage

    @property
    def thread_pool(self):
        """
        Returns aucote thread pool

        Returns:
            ThreadPool

        """
        return self._thread_pool

    def run_scan(self, as_service=True):
        """
        Start scanning ports.

        Returns: None

        """

        try:
            self.storage_thread = StorageThread(filename=self.filename, aucote=self)
            self.storage_thread.start()

            self.thread_pool.start()

            self.watch_task = WatchdogTask(file=cfg.get('config_filename'), action=self.graceful_stop, executor=self)
            if as_service:
                self.add_task(self.watch_task)

            self.scan_task = ScanTask(executor=self, as_service=as_service)
            self.add_task(self.scan_task)
            self.started = True

            self.thread_pool.join()
            self.thread_pool.stop()
            self.storage_thread.stop()

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

    def add_task(self, task):
        """
        Add task for executing

        Args:
            task (Task):

        Returns:
            None

        """
        log.debug('Added task: %s', task)
        self.thread_pool.add_task(task)

    def signal_handler(self, sig, frame):
        """
        Handling signals from operating system. Exits applications (kills all threads).

        Args:
            sig:
            frame:

        Returns:

        """
        log.error("Received signal %s at frame %s. Exiting.", sig, frame)
        self.storage_thread.stop()
        sys.exit(1)

    @property
    def unfinished_tasks(self):
        """
        Get number of unfinished tasks.

        Returns:
            int

        """
        return self.thread_pool.unfinished_tasks

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

    def reload_config(self, file_name):
        """
        Reload configuration and notify threads about it

        Returns:
            None

        """
        cfg.reload(file_name)
        self.scan_task.reload_config()

    def graceful_stop(self):
        """
        Responsible for stopping the threads in graceful way.

        Returns:
            None

        Raises:
            FinishThread - info for watchdog process to stop itself

        """
        self.scan_task.disable_scan()
        self.watch_task.stop()

    def kill(self):
        """
        Kill aucote by sending signal

        Returns:
            None

        """
        os.kill(os.getpid(), signal.SIGTERM)


# =================== start app =================

if __name__ == "__main__":  # pragma: no cover
    chdir(dirname(realpath(__file__)))

    main()
