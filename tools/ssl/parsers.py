"""
Parsers for testssl

"""
import json
from pathlib import Path

from tools.common.parsers import Parser
from tools.ssl.structs import SSLResults


class SSLParser(Parser):
    """
    Main parser of testssl output

    """
    def __init__(self, filename):
        self.filename = filename
        super(SSLParser, self).__init__()

    def parse(self, *args, **kwargs):
        """
        Parses output json file and returns SSLResults

        Args:
            *args:
            **kwargs:

        Returns:
            SSLResults

        """
        file = Path(self.filename)
        text = "[{content}]".format(content=file.read_text())
        return SSLResults(json.loads(text))
