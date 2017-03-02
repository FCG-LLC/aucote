"""
Thread responsible for local storage

"""
import ipaddress
from threading import Thread
import logging as log
from queue import Queue, Empty

import time

from fixtures.exploits import Exploit
from structs import StorageQuery, Port, Node, TransportProtocol, Scan
from utils.storage import Storage


class StorageThread(Thread):
    """
    Class which is separate thread. Creates and manages local storage

    """
    def __init__(self, filename):
        super(StorageThread, self).__init__()
        self.name = "Storage"
        self._filename = ""
        self.filename = filename
        self._queue = Queue()
        self._storage = Storage(self.filename)
        self.finish = False

    def run(self):
        """
        Run infinite loop. while loop takes queries from queue and execute them

        Args:
            *args:
            **kwargs:

        Returns:
            None

        """
        self._storage.connect()
        self._storage.init_schema()

        while not self.finish:
            try:
                query = self._queue.get(timeout=1)
            except Empty:
                continue

            self._storage.execute(query)
            self._queue.task_done()
        self._storage.close()
        log.debug("Exit")

    def add_query(self, query):
        """
        Adds query to the queue

        Args:
            query:

        Returns:
            returns query
        """
        self._queue.put(query)
        return query

    def stop(self):
        """
        Stop thread

        Returns:
            None

        """
        log.info("Stopping storage")
        self.finish = True

    @property
    def storage(self):
        """
        Handler to local storage

        Returns:
            Storage

        """
        return self._storage

    def get_ports(self, pasttime=900):
        """
        Returns all ports from local storage

        Returns:
            list

        """

        ports = []

        query = self.add_query(StorageQuery(*self._storage.get_ports(pasttime)))
        query.semaphore.acquire()

        for port in query.result:
            ports.append(Port(node=Node(node_id=port[0], ip=ipaddress.ip_address(port[1])), number=port[2],
                              transport_protocol=TransportProtocol.from_iana(port[3])))
        return ports

    def get_ports_by_node(self, node, pasttime=0, timestamp=None):
        """
        Get node's ports after given timestamp or for pasttime
        Args:
            node (Node):
            pasttime (float):
            timestamp (float):

        Returns:
            list

        """
        ports = []

        if timestamp is None:
            timestamp = time.time() - pasttime

        query = self.add_query(StorageQuery(*self._storage.get_ports_by_node(node, timestamp)))
        query.semaphore.acquire()

        for row in query.result:
            port = Port(node=node, number=row[2], transport_protocol=TransportProtocol.from_iana(row[3]))
            port.scan = Scan(start=port.node.scan.start)
            ports.append(port)

        return ports

    def get_ports_by_nodes(self, nodes, pasttime=0, timestamp=None):
        """
        Get nodes' ports after given timestamp or for pasttime

        Args:
            node (Node):
            pasttime (float):
            timestamp (float):

        Returns:
            list

        """
        ports = []

        if timestamp is None:
            timestamp = time.time() - pasttime

        query = self.add_query(StorageQuery(*self._storage.get_ports_by_nodes(nodes, timestamp)))
        query.semaphore.acquire()

        for row in query.result:
            node = nodes[nodes.index(Node(node_id=row[0], ip=ipaddress.ip_address(row[1])))]
            port = Port(node=node, number=row[2], transport_protocol=TransportProtocol.from_iana(row[3]))
            port.scan = Scan(start=port.node.scan.start)
            ports.append(port)

        return ports

    def get_nodes(self, pasttime=0, timestamp=None):
        """
        Returns all nodes from local storage

        Returns:
            list

        """

        nodes = []

        query = self.add_query(StorageQuery(*self._storage.get_nodes(pasttime, timestamp)))
        query.semaphore.acquire()

        for node in query.result:
            nodes.append(Node(node_id=node[0], ip=ipaddress.ip_address(node[1])))
        return nodes

    def get_scan_info(self, port, app):
        """
        Gets scan details based on provided port and app name

        Args:
            port (Port):
            app (str): app name

        Returns:
            list - list of dictionaries with keys: exploit, port, scan_start, scan_end

        """
        return_value = []

        query = self.add_query(StorageQuery(*self._storage.get_scan_info(port, app)))

        query.semaphore.acquire()

        for row in query.result:
            return_value.append({
                "exploit": Exploit(exploit_id=row[0]),
                "port": Port(node=Node(node_id=row[3], ip=ipaddress.ip_address(row[4])), number=row[6],
                             transport_protocol=TransportProtocol.from_iana(row[5])),
                "scan_start": row[7] or 0.,
                "scan_end": row[8] or 0.,
                "exploit_name": row[2]
            })

        return return_value

    def save_ports(self, ports):
        """
        Save ports to storage

        Args:
            ports (list):

        Returns:
            None

        """
        self.add_query(self._storage.save_ports(ports))

    def save_node(self, node):
        """
        Save node to storage

        Args:
            node (Node):

        Returns:
            None

        """
        self.add_query(self._storage.save_node(node))

    def save_nodes(self, nodes):
        """
        Save nodes to storage

        Args:
            nodes (list):

        Returns:
            None

        """
        self.add_query(self._storage.save_nodes(nodes))

    def save_scan(self, exploit, port):
        """
        Save scan to storage

        Args:
            exploit (Exploit):
            port (Port):

        Returns:
            None

        """
        self.add_query(self._storage.save_scan(exploit, port))

    def save_scans(self, exploits, port):
        """
        Save scans to storage

        Args:
            exploits (list):
            port (Port):

        Returns:
            None

        """
        self.add_query(self._storage.save_scans(exploits, port))

    def clear_scan_details(self):
        """
        Clear scan details in storage

        Returns:
            None

        """
        self.add_query(self._storage.clear_scan_details())

    def create_tables(self):
        """
        Create tables

        Returns:
            None

        """
        self.add_query(self._storage.create_tables())
