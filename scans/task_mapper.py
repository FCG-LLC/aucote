"""
Class responsible for mapping scans and port, service
"""
from aucote_cfg import cfg
from scans.hydra_scripts_cfg import SERVICE_TO_SCRIPTS_HYDRA
from scans.tasks import NmapPortScanTask
from tools.hydra.base import HydraBase, HydraScriptTask
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
        if cfg.get('tools.hydra.enable') and port.service_name in SERVICE_TO_SCRIPTS_HYDRA.keys():
            self._executor.add_task(SERVICE_TO_SCRIPTS_HYDRA[port.service_name](executor=self._executor, port=port))
