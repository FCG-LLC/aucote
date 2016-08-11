"""
This is executable file of aucote project.
"""

import argparse
import logging as log
from os import chdir
from os.path import dirname, realpath

from scans import Executor
import utils.log as log_cfg
from utils.time import PeriodicTimer, parse_period
from database.serializer import Serializer
from aucote_cfg import cfg, load as cfg_load
from utils.kudu_queue import KuduQueue

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

    log_cfg.config(cfg.get('logging.file'), cfg.get('logging.level'))
    log.info("%s, version: %s.%s.%s", APP_NAME, *VERSION)

    if args.cmd == 'scan':
        run_scan()
    elif args.cmd == 'service':
        run_service()
    elif args.cmd == 'syncdb':
        run_syncdb()

# =============== functions ==============

def run_scan():
    """
    Start scanning ports.
    Returns: None
    """
    with KuduQueue(cfg.get('kuduworker.queue.address')) as kudu_queue:
        executor = Executor(kudu_queue)
        executor.run()


def run_service():
    """
    Run service for periodic scanning
    Returns:

    """
    scan_period = parse_period(cfg.get('service.scans.period'))
    timer = PeriodicTimer(scan_period, run_scan)
    timer.loop()


def run_syncdb():
    """
    Synchronize local exploits database with Kudu
    Returns:

    """
    with KuduQueue(cfg.get('kuduworker.queue.address')) as kudu_queue:
        from fixtures.exploits import read_exploits
        exploits = read_exploits()
        serializer = Serializer()
        for exploit in exploits:
            kudu_queue.send_msg(serializer.serialize_exploit(exploit))


# =================== start app =================

if __name__ == "__main__":
    dir_path = dirname(realpath(__file__))
    chdir(dir_path)

    main()
