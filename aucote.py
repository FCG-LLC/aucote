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
from scans import Executor

from structs import Node
import utils.log as log_cfg
from utils.exceptions import NmapUnsupported, TopdisConnectionException
from utils.storage import Storage
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

    aucote = Aucote(exploits)

    if args.cmd == 'scan':
        nodes = []
        if args.host_ip and args.host_id:
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

    def __init__(self, exploits):
        self.exploits = exploits

    def run_scan(self, nodes=None):
        """
        Start scanning ports.
        Returns: None
        """

        with KuduQueue(cfg.get('kuduworker.queue.address')) as kudu_queue:
            with Storage(filename=cfg.get('service.scans.storage')) as storage:
                storage.clear_scan_details()
                try:
                    executor = Executor(kudu_queue=kudu_queue, exploits=self.exploits, nodes=nodes, storage=storage)
                    executor.run()
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
        with KuduQueue(cfg.get('kuduworker.queue.address')) as kudu_queue:
            serializer = Serializer()
            for exploit in self.exploits:
                kudu_queue.send_msg(serializer.serialize_exploit(exploit))


# =================== start app =================

if __name__ == "__main__": # pragma: no cover
    chdir(dirname(realpath(__file__)))
    main()
