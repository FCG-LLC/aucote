"""
Provides class for proceeding Hydra-THC output

"""

import re
import logging as log

from tools.common.parsers import Parser
from tools.hydra.structs import HydraResults, HydraResult


class HydraParser(Parser):
    """
    This class is responsible for parsing Hydra output

    """

    INFO_PATTERN = r"(?P<info_message>.*)"
    MESSAGE_PATTERN = r"^\[(?P<type>(DATA|ERROR|WARNING))\] (?P<message>.*?)$"
    SUCCESS_PATTERN = r"^\[(?P<port>\d*?)\]\[(?P<service>[\w\-]*?)\]\s+host:\s(?P<host>[\w\.]*?)\s{3}login:\s" \
                      r"(?P<login>.*?)\s{3}password:\s(?P<password>(.*?))$"

    SUMMARY_PATTERN = r"^(?P<success_number>\d+) of (?P<all_number>\d+) target (successfully |)completed, " \
                      r"(?P<valid_passwords>\d+) valid password(s|) found$"

    ALL_PATTERN = "((?P<message_match>{1})|(?P<success_match>{2})|(?P<summary_match>{3})|(?P<info_match>{0}))".format(
        INFO_PATTERN, MESSAGE_PATTERN, SUCCESS_PATTERN, SUMMARY_PATTERN)

    regex_message = re.compile(MESSAGE_PATTERN)
    regex_success = re.compile(SUCCESS_PATTERN)
    regex_summary = re.compile(SUMMARY_PATTERN)
    regex_all = re.compile(ALL_PATTERN)

    @classmethod
    def parse(cls, output):
        """
        Parses output and return collection of Hydra Results

        Args:
            output(str):

        Returns:
            HydraResults

        """
        results = HydraResults()
        for line in output.split("\n"):
            match = cls.regex_all.match(line)

            if match.group('success_match'):
                log.debug("Hydra: %s", line)
                results.add(cls.from_re_match(match))

            elif match.group('summary_match'):
                log.debug("Hydra: %s", line)
                results.success = int(match.group('success_number'))
                results.all = int(match.group('all_number'))

            elif match.group('message_match'):
                log.debug("Hydra: %s", match.group('message'))
            elif line:
                log.debug("Hydra: Unrecognized message: %s", line)

        return results

    @classmethod
    def from_output(cls, output):
        """
        Converts hydra output line to Hydra Result

        Args:
            output (str):

        Returns:
            HydraResult|None

        """
        return cls.from_re_match(cls.regex_success.match(output))

    @classmethod
    def from_re_match(cls, match):
        """
        Converts matching regex to Hydra Result

        Args:
            match:

        Returns:
            HydraResult|None

        """
        if not match:
            return None

        return HydraResult(
            service=match.group('service'),
            host=match.group('host'),
            login=match.group('login'),
            password=match.group('password'),
            port=int(match.group('port'))
        )
