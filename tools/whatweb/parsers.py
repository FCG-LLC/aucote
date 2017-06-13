"""
Parsers for WhatWeb output

"""
import re
import logging as log
import ujson as json

from tools.common.parsers import Parser
from tools.whatweb.structs import WhatWebPlugin, WhatWebTarget, WhatWebResult


class WhatWebParser(Parser):
    """
    Parser of WhatWeb tool output

    """
    PLUGIN_OUTPUT_REGEX = re.compile(r"\[(.*?)\]")
    PLUGIN_NAME_REGEX = re.compile(r"^\W*(?P<name>.*?)(\[|$)")
    OUTPUT_LINE_REGEX = re.compile(r'(?P<address>.*?) \[(?P<status_code>\d+) (?P<status>.*?)\] (?P<plugins>.*)')

    def _get_plugin_from_dict(self, name, data):
        return WhatWebPlugin(name=name, **data)

    def _get_target_from_dict(self, data):
        return_value = WhatWebTarget(uri=data.get('target'), status=int(data.get('http_status')))
        return_value.plugins = [self._get_plugin_from_dict(name, plugin) for name, plugin in
                                data.get('plugins', {}).items()]
        return return_value

    def parse_json(self, stdout, stderr):
        """
        Parses output in json format and returns WhatWebResult

        Args:
            stdout (str):
            stderr (str):

        Returns:
            WhatWebResult | list

        """
        if stderr:
            log.error(stderr)
        data = json.loads(stdout)
        targets = [self._get_target_from_dict(target) for target in data if target]
        if not targets:
            return []
        return WhatWebResult(targets=targets)

    def parse(self, *args, **kwargs):
        return self.parse_json(*args, **kwargs)

    def parse_text(self, stdout, stderr):
        """
        Parses WhatWeb output and returns result
        Args:
            stdout (str):
            stderr (str):

        Returns:
            WhatWebResult

        """
        return WhatWebResult(targets=list(filter(None, map(self._parse_line, filter(None, stdout.split('\n'))))))

    def _parse_plugin_string(self, text):
        """
        Parses plugin string

        Args:
            text (str):

        Returns:
            WhatWebPlugin | None

        """
        outputs = self.PLUGIN_OUTPUT_REGEX.findall(text)
        name = self._get_plugin_name(text)
        if not name:
            return
        return WhatWebPlugin(string=outputs, name=name)

    def _get_plugin_name(self, text):
        """
        Gets plugin name basing on plugin string

        Args:
            text (str):

        Returns:
            str | None

        """
        match = self.PLUGIN_NAME_REGEX.match(text)
        if match:
            return match.group('name')
        else:
            log.error("Parsing error for: %s", text)

    def _parse_line(self, text):
        """
        Parses output line

        Args:
            text (str):

        Returns:
            WhatWebTarget | None

        """
        result = self.OUTPUT_LINE_REGEX.match(text)
        if not result:
            log.error('Parsing error for %s', text)
            return

        return_value = WhatWebTarget()
        return_value.uri = result.group('address')
        return_value.status = int(result.group('status_code'))
        return_value.plugins = [self._parse_plugin_string(plugin_output)
                                for plugin_output in result.group('plugins').split(', ')]

        return return_value
