'''
Contains all Flask views
'''

from .app import app
from dateutil.parser import parse as time_parse
import datetime
from flask import Response, request, jsonify
from database.facades import ApiDb
from aucote_cfg import cfg

def new_result():
    '''
    Creates base for response.

    Returns:
        JSON-compatible structure
    '''
    return {
        'meta': {
            'apiVersion': '1.0.0',
            'requestTime': datetime.datetime.utcnow().isoformat(),
            'url': request.url
        }
    }
def parse_bool(val):
    '''
    Converts string into boolean representation.
    Handles multiple ways of representing true/false

    Args:
        val(str) - string representation of bool.
    Returns:
        True, False or None
    Raises:
        ValueError on unsupported format
    '''
    if not val: return None
    if val in ('y', 'yes', 't', 'true', '1'): return True
    if val in ('n', 'no', 'f', 'false', '0'): return False
    raise ValueError('%s cannot be converted into bool'%val)

@app.route('/api/v1/scans')
def get_scans():
    '''
    This Flask view returns list of performed scans

    Returns:
        JSON HTTP response or HTTP error code on error.
    '''
    with ApiDb(cfg.get('database.credentials')) as db:
        result = new_result()
        result['scans'] = db.get_scans()
        return jsonify(result)

@app.route('/api/v1/ports')
def get_ports():
    '''
    This Flask view returns list of open ports for the given scans

    URL args:
        scanId(str) - optional scan ID from get_scans() result. Defaults to the newest scan.
    Returns:
        JSON HTTP response or HTTP error code on error.
    '''
    result = new_result()
    with ApiDb(cfg.get('database.credentials')) as db:
        scan_id = request.args.get('scanId')
        if scan_id is None: scan_id = db.get_newest_scan()
        result['ports'] = db.get_ports(scan_id)
    return jsonify(result)

@app.route('/api/v1/vulnerabilities')
def get_vulnerabilities():
    '''
    This Flask view returns list of vulnerabilities matching criteria of provided parameters

    URL args:
        scanId(int) - optional scan ID from get_scans() result. Defaults to the newest scan.
        portId(int) - optional port ID from get_ports() result. By default all voulnerabilities of the given scan are returned.
    Returns:
        JSON HTTP response or HTTP error code on error.
    '''
    result = new_result()
    with ApiDb(cfg.get('database.credentials')) as db:
        scan_id = request.args.get('scanId')
        port_id = request.args.get('portId')
        if scan_id is None and port_id is None: scan_id = db.get_newest_scan()
        result['vulnerabilities'] = db.get_vulnerabilities(scan_id, port_id)
        return jsonify(result)

@app.route('/api/v1/exploits')
def get_exploits():
    '''
    This Flask view returns list of exploits supported by this application
    Returns:
        JSON HTTP response or HTTP error code on error.
    '''
    result = new_result()
    with ApiDb(cfg.get('database.credentials')) as db:
        result['exploits'] = db.get_exploits()
        return jsonify(result)




