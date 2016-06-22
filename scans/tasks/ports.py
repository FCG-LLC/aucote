from .base import ScanTask

class PortScanTask():
    '''
    Scans one port using provided vulnerability scan
    '''

    def __init__(self, vuln_cls, port):
        self._vuln_cls = vuln_cls
        self._port = port

    def __call__(self):
        vuln_instance = self._vuln_cls(self._port)
        vulners = vuln_instance.run()
        if not vulners: return
        for vuln in vulners:
            self.db.insert_vulnerability(vuln)




