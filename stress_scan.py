import argparse

from utils.toucan import Toucan

parser = argparse.ArgumentParser(description='Tests compliance of devices.')
parser.add_argument("--threads", help="Number of threads", type=int, default=30)
parser.add_argument("--ports", help="Ports range", type=str, default='T:0-65535,U:0-65535')
parser.add_argument("--network-rate", help="Network rate", type=int, default=1000)
parser.add_argument("--port-rate", help="Ports rate", type=int, default=50)
parser.add_argument("--tool-rate", help="Tools rate", type=int, default=50)
parser.add_argument("--toucan", help="Toucan REST API", type=str, default='http://toucan:3000')
args = parser.parse_args()

def push_config(args):
    config = {
        'service': {
            'scans': {
                'threads': args.threads
            }
        },
        'portdetection': {
            'networks': {
                'include': [
                    '10.12.2.159/32'
                ],
                'exclude': [
                    '10.12.1.0/32'
                ]
            },
            'ports': {
                'include': [args.ports]
            },
            'network_scan_rate': args.network_rate,
            'port_scan_rate': args.port_rate,
            'scan_cron': '1 1 1 1 1',
            'tools_cron': '1 1 1 1 1',
            'port_period': '0s',
            'scan_interval': '0s',
            'scan_enable': True
        },
        'tools': {
            'nmap': {
                'enable': True,
            },
            'common': {
                'rate': args.tool_rate
            }
        }
    }

    toucan = Toucan(args.toucan)
    toucan.push_config(config, overwrite=True)

push_config(args)