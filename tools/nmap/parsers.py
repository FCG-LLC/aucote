"""
Nmap has many modules and every module could have different output.
For every kind of output there are different parsers.

"""
import logging as log


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
        if script is None:
            return None
        return self._parse(script)

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
        if output.startswith("ERROR: "):
            log.warning(output)
            return None
        return output


class NmapVulnParser(NmapParser):
    """
    Returns output only for vurnelable results.

    """
    def _parse(self, script):
        table = script.find('table')
        if table is None:
            return None
        state = table.find("./elem[@key='state']").text
        if state not in ('VULNERABLE', 'LIKELY VULNERABLE', 'VULNERABLE (Exploitable)', 'VULNERABLE (DoS)'):
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
