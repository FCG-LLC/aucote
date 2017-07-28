"""
This module contains task related to port.

"""
import time

from database.serializer import Serializer
from structs import VulnerabilityChange
from utils.task import Task


class PortTask(Task):
    """
    Abstract class for exploit-tasks executed on port

    """
    def __init__(self, port, exploits, *args, **kwargs):
        """
        Initialize variables

        Args:
            port (Port):
            exploit (Exploit):
            *args:
            **kwargs:

        """
        super().__init__(*args, **kwargs)
        self._port = port
        self._current_exploits = exploits

    @property
    def exploit(self):
        """
        Exploit or None if task have more exploits

        Returns:
            Exploit|None

        """
        if len(self.current_exploits) == 1:
            return next(iter(self.current_exploits))
        return None

    def get_vulnerabilities(self, results):
        """
        Gets vulnerabilities based upon results

        Args:
            results(list): list of AucoteHttpHeaderResult

        Returns:
            list: list of Vulneravbilities

        """
        raise NotImplementedError

    @property
    def current_exploits(self):
        """
        List of exploits, which are used by task

        Returns:
            list

        """
        return self._current_exploits[:]

    @current_exploits.setter
    def current_exploits(self, val):
        self._current_exploits = val

    @property
    def port(self):
        """
        Port

        Returns:
            Port

        """
        return self._port

    def diff_with_last_scan(self):
        """
        Differentiate two last scans.

        Obtain exploits scanned in current scan.
        For each exploit check what changed in findings from last scan of this exploits

        Args:

        Returns:
            None

        """
        changes = []

        for exploit in self.current_exploits:
            last_scans = self.storage.get_scans_by_security_scan(port=self.port, exploit=exploit)
            _current_findings = self.storage.get_vulnerabilities(port=self.port, exploit=exploit, scan=self._scan)

            if len(last_scans) < 2:
                _previous_findings = []
            else:
                _previous_findings = self.storage.get_vulnerabilities(port=self.port, exploit=exploit,
                                                                      scan=last_scans[1])

            common_findings = []

            for current_finding in _current_findings:
                for previous_finding in _previous_findings:
                    if current_finding == previous_finding:
                        break

                    if current_finding.is_almost_equal(previous_finding):
                        common_findings.append(
                            {
                                'prev': previous_finding,
                                'curr': current_finding
                            })
                        break

            current_findings = list(set(_current_findings) - set(_previous_findings) -
                                    set(finding['curr'] for finding in common_findings))
            previous_findings = list(set(_previous_findings) - set(_current_findings) -
                                     set(finding['prev'] for finding in common_findings))

            changes.extend(VulnerabilityChange(change_time=time.time(), previous_finding=None,
                                               current_finding=vuln) for vuln in current_findings)

            changes.extend(VulnerabilityChange(current_finding=None, change_time=time.time(),
                                               previous_finding=vuln) for vuln in previous_findings)

            changes.extend(VulnerabilityChange(current_finding=vuln['curr'], change_time=time.time(),
                                               previous_finding=vuln['prev']) for vuln in common_findings)

        self.storage.save_changes(changes)
        for change in changes:
            self.aucote.kudu_queue.send(Serializer.serialize_vulnerability_change(change))
