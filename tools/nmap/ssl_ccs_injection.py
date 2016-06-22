from .base import NmapScript 
from scans.structs import Vulnerability, RiskLevel
import logging as log

class SslCcsInjection(NmapScript):
    NAME = 'ssl-ccs-injection'

    def handle_script(self, script):
        output = script.get('output')
        log.debug('output: %s', repr(output))
        table = script.find('table')
        if table is None: return #no data, probably no response from server, so no problem
        state = table.find("./elem[@key='state']").text
        log.debug('State of port: %s', state)
        if state != 'VULNERABLE': return None
        vulner = Vulnerability()
        vulner.title = table.find("./elem[@key='title']").text
        vulner.description = table.find("./table[@key='description']/elem").text
        vulner.risk_level = RiskLevel.HIGH #TODO: parse output 
        vulner.port = self.port
        return [vulner]

