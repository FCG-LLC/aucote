"""
Contains all tasks related to the WhatWeb tool

"""
from structs import CPEType, Service, Port
from tools.common.command_task import CommandTask
from tools.whatweb.base import WhatWebBase
from tools.whatweb.structs import WHATWEBPLUGINDETAILS
import logging as log


class WhatWebTask(CommandTask):
    """
    This is task for WhatWeb tool. Calls WhatWeb and parses output

    """

    def __init__(self, *args, **kwargs):
        """
        Initialize variables

        Args:
            port (Port):
            *args:
            **kwargs:

        """
        super().__init__(command=WhatWebBase(), *args, **kwargs)

    def prepare_args(self):
        """
        Prepare arguments for command execution

        Returns:
            list

        """
        return str(self.port.url),

    async def execute(self):
        result = await super().execute()
        if not result:
            return

        cpes = []
        for target in result.targets:
            for plugin in target.plugins:
                if not plugin.version:
                    continue
                plugin_details = WHATWEBPLUGINDETAILS.get(plugin.name)
                if not plugin_details:
                    continue

                product = plugin_details[0].get('product')
                cpes.append(
                    Service(cpe=Service.build_cpe(part=CPEType.APPLICATION, vendor=product.vendor,
                                                  product=product.product, version=plugin.version[0]),
                            name=product.product, version=plugin.version[0])
                )

        if not cpes:
            log.debug("No cpes for %s found by whatweb", str(self.port))
            return

        exploits = self.aucote.exploits.find_by_apps(['cve-search'])
        new_port = self.port.copy()
        new_port.apps = cpes

        from scans.task_mapper import TaskMapper  # ToDo: Solve circular dependencies by using context
        await TaskMapper(context=self.context).assign_tasks(port=new_port, scripts=exploits)
