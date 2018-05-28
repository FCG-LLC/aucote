"""
Parsers for testssl

"""
from pathlib import Path
import ujson as json

from tools.common.parsers import Parser
from tools.ssl.structs import SSLResults, SSLResult, SSLSeverity


class SSLParser(Parser):
    """
    Main parser of testssl output

    """
    def __init__(self, tempfile):
        self.tempfile = tempfile
        super(SSLParser, self).__init__()

    def parse(self, *args, **kwargs) -> 'SSLResults':
        """
        Parses output json file and returns SSLResults
        """
        file = Path(self.tempfile.name)
        text = "[{content}]".format(content=file.read_text(encoding='utf-8').strip(","))
        return self._dict_to_results(json.loads(text))

    def _dict_to_results(self, data: dict) -> 'SSLResults':
        """
        Create results from dict
        """
        return_value = SSLResults()
        return_value.results = [self._dict_to_result(single_json) for single_json in data]
        return return_value

    def _dict_to_result(self, data: dict) -> 'SSLResult':
        """
        Create result from dict
        """
        return_value = SSLResult()
        return_value.id = data.get('id')
        return_value.ip = data.get('ip')
        return_value.port = data.get('port')
        return_value.severity = SSLSeverity.from_name(data.get('severity'))
        return_value.cve = data.get('cve')
        return_value.cwe = data.get('cwe')
        return_value.finding = data.get('finding')
        return return_value
