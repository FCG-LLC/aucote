"""
Nmap has many modules and every module could have different output.
For every kind of output there are different parsers.

"""
import logging as log
import re


class NmapParser(object):
    """
    Base parser

    """
    def parse(self, script):
        """
        Check if script is correct output and execute detailed parser

        Args:
            script:

        Returns:

        """
        return self._parse(script) if script is not None else None

    def _parse(self, script):
        """
        Detailed abstract parser for output script

        Args:
            script (ElementTree.ElementTree):

        Returns:
            str

        """
        raise NotImplementedError


class NmapInfoParser(NmapParser):
    """
    Parser for info script. There is no filter, just returns the output.

    """
    def _parse(self, script):
        output = script.get('output').strip()
        if not output:
            return None
        if output.startswith("ERROR: ") or "SMB: Couldn't find a NetBIOS name that works for the server. Sorry!" in \
                output:
            log.warning(output)
            return None
        return output


class NmapVulnParser(NmapParser):
    """
    Returns output only for vulnerable results.

    """
    def _parse(self, script):
        state = script.find("./table/elem[@key='state']")
        if state is None or state.text not in ('VULNERABLE', 'LIKELY VULNERABLE', 'VULNERABLE (Exploitable)',
                                               'VULNERABLE (DoS)'):
            return None  # TODO: add likelihood to vulnerability
        return script.get('output').strip()


class NmapBrutParser(NmapParser):
    """
    Returns output for brute module.

    """
    def _parse(self, script):
        tables = script.find('table')
        if not tables:
            return None

        accounts = []
        hashes = []

        for table in tables:
            if table.find("./elem[@key='state']").text == 'Valid credentials':
                accounts.append("{0}:{1}".format(table.find("./elem[@key='username']").text,
                                                 table.find("./elem[@key='password']").text))
            else:
                hashes.append("{0}:{1}:{2}".format(table.find("./elem[@key='username']").text,
                                                   table.find("./elem[@key='password']").text,
                                                   table.find("./elem[@key='state']").text))

        return_value = "Accounts:\n{0}\n\nHashes:\n{1}".format("\n".join(accounts), "\n".join(hashes))
        return return_value


class NmapHTTPWebsphereConsoleParser(NmapInfoParser):
    REGEX = re.compile("(?P<name>^.*?)( at )(?P<path>.*)")
    UNKNOWN = "Unknown"

    def _parse(self, script):
        output = super(NmapHTTPWebsphereConsoleParser, self)._parse(script=script)
        consoles = []
        for line in output.split("\n"):
            regex_match = self.REGEX.match(line)
            if not regex_match:
                continue

            regex_result = regex_match.groupdict()
            if regex_result.get('name', '').strip() == self.UNKNOWN:
                continue

            consoles.append(line)

        if not consoles:
            return None

        return "consoles: \n{0}".format("\n".join(consoles))
