from aucote_cfg import cfg, load as cfg_load
import argparse
from utils.kudu_queue import KuduQueue
import datetime
from scans import Executor
import logging as log
import utils.log as log_cfg
from utils.time import PeriodicTimer, parse_period
from database.serializer import Serializer

#constants
VERSION = (0,1,0)
APP_NAME = 'Automated Compliance Tests'

def run_scan():
    #with ScanDb(cfg.get("database.credentials")) as scan_db:
    with KuduQueue(cfg.get('kuduworker.queue.address')) as kudu_queue:
        executor = Executor(kudu_queue)
        executor.run()
        
        
def run_service():
    #scanning
    scan_period = parse_period(cfg.get('service.scans.period'))
    timer = PeriodicTimer(scan_period, run_scan())
    timer.loop()

def run_syncdb():
    with KuduQueue(cfg.get('kuduworker.queue.address')) as kudu_queue:
        from fixtures.exploits import read_exploits
        exploits = read_exploits()
        serializer = Serializer()
        for exploit in exploits:
            kudu_queue.send_msg(serializer.serialize_exploit(exploit))

#============== main app ==============
print("%s, version: %s.%s.%s"%((APP_NAME,) + VERSION));

#parse arguments
parser = argparse.ArgumentParser(description='Tests compliance of devices.')
parser.add_argument("--cfg", help="config file path")
parser.add_argument('cmd', help="aucote command", type=str, default='service', choices=['scan', 'service', 'syncdb'], nargs='?')
args = parser.parse_args()

#read configuration
cfg_load(args.cfg)

log_cfg.config(cfg.get('logging.file'), cfg.get('logging.level'))
log.info("%s, version: %s.%s.%s", APP_NAME, *VERSION)

if args.cmd == 'scan':
    run_scan()
elif args.cmd == 'service':
    run_service()
elif args.cmd == 'syncdb':
    run_syncdb()