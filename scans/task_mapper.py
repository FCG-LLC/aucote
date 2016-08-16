"""
Class responsible for mapping scans and port, service
"""
from scans.tasks import NmapPortScanTask
# from tools.hydra.base import HydraScriptTask
from .nmap_scripts_cfg import SERVICE_TO_SCRIPTS, PORT_TO_SCRIPTS


class TaskMapper:
    """
    Assign tasks for a provided port
    """

    def __init__(self, executor):
        self._executor = executor

    def assign_tasks(self, port):
        """
        Assign tasks for a provided port
        """
        all_scripts = set()
        all_scripts.update(SERVICE_TO_SCRIPTS.get(port.service_name, tuple()))
        all_scripts.update(PORT_TO_SCRIPTS.get(port.transport_protocol.name, dict()).get(port.number, tuple()))
        self._executor.add_task(NmapPortScanTask(self._executor, port, all_scripts))

        # Hydra scanning
        # if port.service_name in HydraBase.SUPORTED_SERVICES:
        #     self._executor.add_task(HydraScriptTask(executor=self._executor, port))
