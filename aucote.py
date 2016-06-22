from aucote_cfg import cfg, load as cfg_load
import argparse
from database.facades import ScanDb
from utils.database import MigrationManager
import datetime
from scans import Executor
import logging as log
import utils.log as log_cfg
from utils.time import PeriodicTimer
from threading import Thread

#constants
VERSION = (0,1,0)
APP_NAME = 'Automated Compliance Tests'

def api_thread():
    from api import app
    app.run(cfg)

def run_api():
    api_thread()

def run_scan():
    start = datetime.datetime.utcnow()
    with ScanDb(cfg.get("database.credentials")) as scan_db:
        scan_id = scan_db.insert_scan(start)
        executor = Executor(scan_db, scan_id)
        executor.run()
        end = datetime.datetime.utcnow()
        scan_db.update_scan(scan_id, end)
        
def run_service():
    thread = Thread(target=api_thread)
    thread.start()
    #scanning
    scan_period = parse_period(cfg.get('service.scans.period'))
    timer = PeriodicTimer(scan_period, run_scan())
    timer.loop()

def run_syncdb():
    mm = MigrationManager(cfg.get("database.credentials"), cfg.get("database.migration.path"))
    mm.migrate()



#============== main app ==============
print("%s, version: %s.%s.%s"%((APP_NAME,) + VERSION));

#parse arguments
parser = argparse.ArgumentParser(description='Tests compliance of devices.')
parser.add_argument("--cfg", help="config file path")
parser.add_argument('cmd', help="aucote command", type=str, default='service', choices=['scan','syncdb', 'service', 'api'], nargs='?')
args = parser.parse_args()

#read configuration
cfg_load(args.cfg)

log_cfg.config(cfg.get('logging.file'), cfg.get('logging.level'))
log.info("%s, version: %s.%s.%s", APP_NAME, *VERSION)

if args.cmd == 'scan':
    run_scan()
elif args.cmd == 'service':
    run_service()
elif args.cmd == 'api':
    run_api()
elif args.cmd == 'syncdb':
    run_syncdb()