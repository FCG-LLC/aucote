from .base import NmapScript 
from scans.structs import Vulnerability, RiskLevel
import logging as log

class SslPoodle(NmapScript):
    NAME = 'ssl-poodle'

    def handle_script(self, script):
        output = script.get('output')
        log.debug('output: %s', repr(output))
        state = script.find("./table[@key='CVE-2014-3566']/elem[@key='state']").text
        log.debug('State of port: %s', state)
        if state != 'VULNERABLE': return None
        vulner = Vulnerability()
        vulner.title = script.find("./table[@key='CVE-2014-3566']/elem[@key='title']").text
        vulner.description = script.find("./table[@key='CVE-2014-3566']/table[@key='description']/elem").text
        vulner.risk_level = RiskLevel.MEDIUM #TODO: parse output 
        vulner.port = self.port
        return [vulner]

