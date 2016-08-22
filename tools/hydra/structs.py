import re
import logging as log

from structs import TransportProtocol, Port
from utils.exceptions import HydraPortMismatchException


class HydraResults(object):
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

    def __init__(self, output, port=None):
        self._results = []
        self.success = None
        self.fail = None
        self.all = None

        for line in output.split("\n"):
            match = self.regex_all.match(line)

            if match.group('success_match'):
                log.debug("Hydra: {0}".format(line))
                self._results.append(HydraResult.from_re_match(match, port))

            elif match.group('summary_match'):
                log.debug("Hydra: {0}".format(line))
                self.success = int(match.group('success_number'))
                self.all = int(match.group('all_number'))
                self.fail = self.all - self.success

            elif match.group('message_match'):
                log.debug("Hydra: {0}".format(match.group('message')))
            elif line:
                log.debug("Hydra: Unrecognized message: {0}".format(line))

    def __getitem__(self, item):
        return self._results[item]

    def __len__(self):
        return len(self._results)


class HydraResult(object):

    def __init__(self, port=None, service=None, host=None, login=None, password=None):
        self.port = port
        self.service = service
        self.host = host
        self.login = login
        self.password = password

    @classmethod
    def from_output(cls, output, port=None):
        return cls.from_re_match(HydraResults.regex_success.match(output), port)

    @classmethod
    def from_re_match(cls, match, port=None):
        if not match:
            return None

        if not port:
            port = Port()
            port.number = int(match.group('port'))
            port.transport_protocol = TransportProtocol.TCP
        elif port.number != int(match.group('port')) \
                or port.transport_protocol != TransportProtocol.TCP:
            raise HydraPortMismatchException

        return cls(
            port=port,
            service=match.group('service'),
            host=match.group('host'),
            login=match.group('login'),
            password=match.group('password')
        )

    def __str__(self):
        return "login: {2}\tpassword: {3}".format(self.host, self.port.number, self.login,
                                                                       self.password)
