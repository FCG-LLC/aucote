"""
Provide class for tasks

"""
import logging as log
import time

from database.serializer import Serializer


class Task(object):
    """
    Base class for tasks, e.g. scan, nmap, hydra

    """
    def __init__(self, aucote, scan):
        """
        Assign executor

        """
        self.aucote = aucote
        self.creation_time = time.time()
        self.start_time = None
        self._name = None
        self._scan = scan

    @property
    def kudu_queue(self):
        """
        Return executors kudu_queue

        """
        return self.aucote.kudu_queue

    def __call__(self, *args, **kwargs):
        """
        Call executed by executor

        """
        raise NotImplementedError

    def send_msg(self, msg):
        """
        Send msg to kudu_queue

        """
        return self.kudu_queue.send_msg(msg)

    def store_scan_end(self, exploits, port):
        """
        Stores scan end in local storage

        Args:
            exploits (Exploits):
            port (Port):

        Returns:
            None

        """
        self.aucote.storage.save_security_scans(exploits=exploits, port=port)

    def store_vulnerability(self, vuln):
        """
        Saves vulnerability into database (kudu)

        Args:
            vuln (Vulnerability):

        Returns:
            None

        """
        log.debug('Found vulnerability: port=%s exploit=%s output=%s', vuln.port, vuln.exploit.id, vuln.output)
        msg = Serializer.serialize_port_vuln(vuln.port, vuln)
        self.kudu_queue.send_msg(msg)

        self.aucote.storage.save_vulnerabilities(vulnerabilities=[vuln], scan=self._scan)

    def store_vulnerabilities(self, vulnerabilities):
        """
        Saves vulnerabilities into storage

        Args:
            vulnerabilities (list):

        Returns:
            None

        """
        log.info("Saving %i vulnerabilities", len(vulnerabilities))

        if vulnerabilities:
            for vulnerability in vulnerabilities:
                self.store_vulnerability(vulnerability)

        self.aucote.storage.save_vulnerabilities(vulnerabilities=vulnerabilities, scan=self._scan)

        return None

    def reload_config(self):
        """
        Should be executed by executor when, configuration is reloaded

        Returns:
            None

        """
        pass

    @property
    def storage(self):
        """
        Storage for aucote application

        Returns:
            None

        """
        return self.aucote.storage
