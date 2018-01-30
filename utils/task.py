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
    def __init__(self, context, scan):
        """
        Assign executor

        """
        self.context = context
        self.creation_time = time.time()
        self.start_time = None
        self.finish_time = None
        self._name = None
        self._scan = scan

    @property
    def aucote(self):
        return self.context.aucote

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
        self.aucote.storage.save_security_scans(exploits=exploits, port=port, scan=self._scan)

    def store_vulnerability(self, vuln):
        """
        Saves vulnerability into database (kudu)

        Args:
            vuln (Vulnerability):

        Returns:
            None

        """
        log.debug('Found vulnerability %s for %s', vuln.exploit.id, vuln.port)
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
            Storage

        """
        return self.aucote.storage

    def __str__(self):
        return "{} for {}".format(self.__class__.__name__, self._scan.scanner)

    def cancel(self):
        """
        Cancels tasks. As for now part of tasks are executed in ioloop and terminated externally by stopping ioloop,
        the default behaviour is to do nothing
        """
        pass

    def clear(self):
        """
        Clear after task. By default task doesn't require any special clearing,
        some task (especially which uses external tools) can need it

        """
        pass

    def is_end(self):
        """
        Checks if task finished
        """
        if self.finish_time is None:
            return False

        return True
