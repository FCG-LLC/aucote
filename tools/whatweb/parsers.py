"""
Parsers for WhatWeb output

"""
import ujson as json
import re
import logging as log

from tools.common.parsers import Parser
from tools.whatweb.structs import WhatWebPlugin, WhatWebTarget, WhatWebResult


class WhatWebParser(Parser):
    PLUGIN_OUTPUT_REGEX = re.compile("\[(.*?)\]")
    PLUGIN_NAME_REGEX = re.compile("^\W*(?P<name>.*?)(\[|$)")
    OUTPUT_LINE_REGEX = re.compile('(?P<address>.*?) \[(?P<status_code>\d+) (?P<status>.*?)\] (?P<plugins>.*)')

    def _get_plugin_from_dict(self, name, data):
        return_value = WhatWebPlugin()
        return_value.name = name
        return_value.os = data.get('os')
        return_value.string = data.get('string', [])
        return_value.account = data.get('account')
        return_value.model = data.get('model')
        return_value.firmware = data.get('firmware')
        return_value.module = data.get('module')
        return_value.filepath = data.get('filepath')
        return return_value

    def _get_target_from_dict(self, data):
        return_value = WhatWebTarget()
        return_value.uri = data.get('target')
        return_value.status = int(data.get('http_status'))
        return_value.plugins = [self._get_plugin_from_dict(name, plugin) for name, plugin in
                                data.get('plugins', {}).items()]
        return return_value

    def parse_json(self, stdout, stderr):
        data = json.loads(stdout)
        return_value = WhatWebResult()
        return_value.targets = [self._get_target_from_dict(target) for target in data if target]
        return return_value

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
        return_value = WhatWebResult()
        for line in stdout.split('\n'):
            if not line:
                continue
            result = self._parse_line(line)
            if not result:
                continue
            return_value.targets.append(result)
        return return_value

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
        return_value = WhatWebPlugin()
        return_value.string = outputs
        return_value.name = name
        return return_value

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
