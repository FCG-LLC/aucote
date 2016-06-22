from .base import NmapScript 
from scans.structs import Vulnerability, RiskLevel
import logging as log

class SslHeartbleed(NmapScript):
    NAME = 'ssl-heartbleed'

    def handle_script(self, script):
        output = script.get('output')
        log.debug('output: %s', repr(output))
        state = script.find("./table[@key='NMAP-1']/elem[@key='state']").text
        log.debug('State of port: %s', state)
        if state != 'VULNERABLE': return None
        vulner = Vulnerability()
        vulner.title = script.find("./table[@key='NMAP-1']/elem[@key='title']").text
        vulner.description = script.find("./table[@key='NMAP-1']/table[@key='description']/elem").text
        vulner.risk_level = RiskLevel.HIGH #TODO: parse output 
        vulner.port = self.port
        return [vulner]

