"""
This is executable file of aucote project.
"""

import argparse
import logging as log
import sched
from os import chdir
from os.path import dirname, realpath

import time

from fixtures.exploits import Exploits
from scans.scan_task import ScanTask
from scans.task_mapper import TaskMapper

from structs import Node
import utils.log as log_cfg
from utils.exceptions import NmapUnsupported, TopdisConnectionException
from utils.storage import Storage
from utils.threads import ThreadPool
from utils.time import parse_period
from utils.kudu_queue import KuduQueue

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
    parser.add_argument("--host_ip", help="Host ip for single scan")
    parser.add_argument("--host_id", help="Host id for single scan")
    args = parser.parse_args()

    # read configuration
    cfg_load(args.cfg)

    log_cfg.config(cfg.get('logging'))
    log.info("%s, version: %s.%s.%s", APP_NAME, *VERSION)

    exploit_filename = cfg.get('fixtures.exploits.filename')
    try:
        exploits = Exploits.read(file_name=exploit_filename)
    except NmapUnsupported as exception:
        log.error("Cofiguration seems to be invalid. Check ports and services or contact with collective-sense",
                  exc_info=exception)
        exit(1)

    with KuduQueue(cfg.get('kuduworker.queue.address')) as kudu_queue:

        with Storage(filename=cfg.get('service.scans.storage')) as storage:
            aucote = Aucote(exploits=exploits, kudu_queue=kudu_queue, storage=storage)

            if args.cmd == 'scan':
                nodes = []
                if args.host_ip is not None and args.host_id is not None:
                    node = Node(ip=args.host_ip, node_id=args.host_id)
                    nodes.append(node)

                aucote.run_scan(nodes=nodes)
            elif args.cmd == 'service':
                aucote.run_service()
            elif args.cmd == 'syncdb':
                aucote.run_syncdb()


# =============== functions ==============


class Aucote(object):
    """
    Main aucote class. It Provides run functions (service, single instance, sync db)
    """

    def __init__(self, exploits, kudu_queue, storage):
        self.exploits = exploits
        self._thread_pool = ThreadPool(cfg.get('service.scans.threads'))
        self._kudu_queue = kudu_queue
        self._storage = storage
        self.task_mapper = TaskMapper(self)

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

    @property
    def thread_pool(self):
        """
        Returns aucote thread pool

        Returns:
            ThreadPool
        """
        return self._thread_pool

    def run_scan(self, nodes=None):
        """
        Start scanning ports.
        Returns: None
        """

        self.storage.clear_scan_details()
        try:
            self.add_task(ScanTask(executor=self, nodes=nodes))
            # self.add_task(Executor(aucote=self, nodes=nodes))

            self.thread_pool.start()
            self.thread_pool.join()
            self.thread_pool.stop()
        except TopdisConnectionException:
            log.error("Exception while connecting to Topdis", exc_info=TopdisConnectionException)

    def run_service(self):
        """
        Run service for periodic scanning
        Returns:

        """
        scheduler = sched.scheduler(time.time)
        scan_period = parse_period(cfg.get('service.scans.period'))
        scheduler.enter(0, 1, self.run_scan)
        while True:
            scheduler.run()
            log.info("sleeping %s seconds", scan_period)
            scheduler.enter(scan_period, 1, self.run_scan)

    def run_syncdb(self):
        """
        Synchronize local exploits database with Kudu
        Returns:

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

        """
        log.debug('Added task: %s', task)
        self.thread_pool.add_task(task)


# =================== start app =================

if __name__ == "__main__": # pragma: no cover
    chdir(dirname(realpath(__file__)))
    main()
