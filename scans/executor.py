"""
This is main module of aucote scanning functionality.

"""
import logging as log
import time

from aucote_cfg import cfg
from tools.nmap.tasks.port_info import NmapPortInfoTask
from utils.task import Task
from utils.time import parse_period
from structs import Scan, BroadcastPort


class Executor(Task):
    """
    Gets the information about nodes and starts the tasks

    """

    def __init__(self, ports=None, scan_only=False, nodes=None, *args, **kwargs):
        """
        Init executor. Sets kudu_queue and nodes

        """
        super(Executor, self).__init__(*args, **kwargs)
        self._ports = ports or []
        self.nodes = nodes or []

        self.scan_only = scan_only
        if cfg['service.scans.broadcast']:
            broadcast_port = BroadcastPort()
            broadcast_port.scan = Scan(start=time.time())
            self._ports.append(broadcast_port)

    @property
    def storage(self):
        """
        Returns aucote's storage

        Returns:
            Storage

        """
        return self.aucote.storage

    @property
    def kudu_queue(self):
        """
        Returns aucote's kudu queue

        Returns:
            KuduQueue

        """
        return self.aucote.kudu_queue

    async def run(self):
        """
        Start tasks: scanning nodes and ports

        """
        ports = self.ports
        storage_ports = self.storage.get_ports(parse_period(cfg['service.scans.port_period']))

        ports = self._get_ports_for_scanning(ports, storage_ports)
        log.info("Found %i recently not scanned ports", len(ports))

        self.storage.save_ports(ports)

        for port in ports:
            self.add_async_task(NmapPortInfoTask(aucote=self.aucote, port=port, scan_only=self.scan_only))

    def __call__(self, *args, **kwargs):
        """
        Making executor callable for working as task

        Args:
            *args:
            **kwargs:

        Returns:

        """
        return self.run()

    def add_task(self, task):
        """
        Add task to aucote pool

        Args:
            task (Task):

        Returns:
            None

        """
        return self.aucote.add_task(task)

    def add_async_task(self, task):
        """
        Add async task to aucote pool

        Args:
            task (Task):

        Returns:
            None

        """
        return self.aucote.add_async_task(task)

    @property
    def exploits(self):
        """
        Returns:
            exploits

        """
        return self.aucote.exploits

    @classmethod
    def _get_ports_for_scanning(cls, ports, storage_ports):
        """
        Diff ports for scanning

        Args:
            ports (list):
            storage_ports (list):

        Returns:
            list

        """
        ports = ports[:]

        for port in storage_ports:
            try:
                ports.remove(port)
            except ValueError:
                continue

        return ports

    @property
    def ports(self):
        """
        List of ports

        Returns:
            list - list of Ports

        """
        return self._ports[:]

    @ports.setter
    def ports(self, val):
        self._ports = val
