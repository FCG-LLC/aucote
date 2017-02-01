"""
Thread responsible for local storage

"""
import ipaddress
from threading import Thread

import logging as log
from queue import Queue, Empty

from fixtures.exploits import Exploit
from structs import StorageQuery, Port, Node, TransportProtocol
from utils.storage import Storage


class StorageThread(Thread):
    """
    Class which is separate thread. Creates and manages local storage

    """
    def __init__(self, filename):
        super(StorageThread, self).__init__()
        self.name = "Storage"
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
        self.create_tables()
        self.clear_scan_details()

        while not self.finish:
            try:
                query = self._queue.get(timeout=1)
            except Empty:
                continue

            if isinstance(query, list):
                log.debug("executing %i queries", len(query))
                for row in query:
                    self._storage.cursor.execute(*row)
            elif isinstance(query, StorageQuery):
                try:
                    query.result = self._storage.cursor.execute(*query.query).fetchall()
                except Exception:
                    log.exception("Exception while executing query: %s", query.query[0])
                finally:
                    query.lock.release()
                    self._queue.task_done()
                continue
            else:
                log.debug("executing query: %s", query[0])
                self._storage.cursor.execute(*query)
            self._storage.conn.commit()
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
        query.lock.acquire()

        for port in query.result:
            ports.append(Port(node=Node(node_id=port[0], ip=ipaddress.ip_address(port[1])), number=port[2],
                              transport_protocol=TransportProtocol.from_iana(port[3])))
        return ports

    def get_nodes(self, pasttime=0):
        """
        Returns all nodes from local storage

        Returns:
            list

        """

        nodes = []

        query = self.add_query(StorageQuery(*self._storage.get_nodes(pasttime)))
        query.lock.acquire()

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

        query = self.add_query(StorageQuery(*self._storage.get_scan_info(port,app)))

        query.lock.acquire()

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
        self.add_query(self._storage.save_ports(ports))

    def save_node(self, node):
        self.add_query(self._storage.save_node(node))

    def save_nodes(self, nodes):
        self.add_query(self._storage.save_nodes(nodes))

    def save_scan(self, exploit, port):
        self.add_query(self._storage.save_scan(exploit, port))

    def save_scans(self, exploits, port):
        self.add_query(self._storage.save_scans(exploits, port))

    def clear_scan_details(self):
        self.add_query(self._storage.clear_scan_details())

    def create_tables(self):
        self.add_query(self._storage.create_tables())
