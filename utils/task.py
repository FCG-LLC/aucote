"""
Provide class for tasks

"""
import logging as log
from database.serializer import Serializer


class Task(object):
    """
    Base class for tasks, e.g. scan, nmap, hydra

    """
    def __init__(self, executor):
        """
        Assign executor

        """
        self.executor = executor

    @property
    def kudu_queue(self):
        """
        Return executors kudu_queue

        """
        return self.executor.kudu_queue

    @property
    def exploits(self):
        """
        Return executors exploits

        """
        return self.executor.exploits

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
        self.executor.storage.save_scans(exploits=exploits, port=port)

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
        return self.executor.storage

    def get_info(self):
        return None