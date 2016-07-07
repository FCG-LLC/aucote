import logging as log
from tools.nmap import NmapBase
from ..task_mapper import TaskMapper

class NmapPortInfoTask(NmapBase):
    '''
    Scans one port using provided vulnerability scan
    '''

    def __init__(self, port):
        self._port = port

    def __call__(self):
        args = list()
        args.extend(( '-p', str(self._port.number), '-sV'))
        args.extend( ('--script', 'banner'))
        args.append(str(self._port.node.ip))
        xml = self.call(args)
        banner = xml.find("host/ports/port/script[@id='banner']")
        if banner is None:
            log.warning('No banner for %s', self._port.node.ip)
        else:
            self._port.banner = banner.get('output')
        service = xml.find("host/ports/port/service")
        if service is None:
            log.warning('No service for %s', self._port.node.id)
        else:
            self._port.service_name = service.get('name')
            self._port.service_version = service.get('version')

        #assign tasks
        tm = TaskMapper(self.executor)
        tm.assign_tasks(self._port)


                       