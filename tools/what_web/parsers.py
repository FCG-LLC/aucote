"""
Parsers for WhatWeb output

"""
import re
import logging as log

from tools.common.parsers import Parser
from tools.what_web.structs import WhatWebPluginOutput, WhatWebResult, WhatWebResults


class WhatWebParser(Parser):
    plugin_output_regex = re.compile("\[(.*?)\]")
    plugin_name_regex = re.compile("^\W*(?P<name>.*?)(\[|$)")
    output_line = re.compile('(?P<address>.*?) \[(?P<status_code>\d+) (?P<status>.*?)\] (?P<plugins>.*)')

    def parse(self, stdout, stderr):
        """
        Parses WhatWeb output and returns result
        Args:
            stdout (str):
            stderr (str):

        Returns:
            WhatWebResults

        """
        return_value = WhatWebResults()
        for line in stdout.split('\n'):
            if not line:
                continue
            result = self._parse_line(line)
            if not result:
                continue
            return_value.results.append(result)
        return return_value

    def _parse_plugin_string(self, text):
        """
        Parses plugin string

        Args:
            text (str):

        Returns:
            WhatWebPluginOutput

        """
        outputs = self.plugin_output_regex.findall(text)
        name = self._get_plugin_name(text)
        if not name:
            return
        return_value = WhatWebPluginOutput()
        return_value.outputs = outputs
        return_value.name = name
        return return_value

    def _get_plugin_name(self, text):
        """
        Gets plugin name basing on plugin string

        Args:
            text (str):

        Returns:
            str

        """
        match = self.plugin_name_regex.match(text)
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
            WhatWebResult

        """
        result = self.output_line.match(text)
        if not result:
            log.error('Parsing error for %s', text)
            return

        return_value = WhatWebResult()
        return_value.address = result.group('address')
        return_value.status = result.group('status')
        return_value.status_code = int(result.group('status_code'))
        return_value.plugins = [self._parse_plugin_string(plugin_output)
                                for plugin_output in result.group('plugins').split(', ')]

        return return_value
