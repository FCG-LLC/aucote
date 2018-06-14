"""
Provides Skipfish tool

"""
import logging as log

from tools.base import Tool
from tools.skipfish.tasks import SkipfishScanTask


class SkipfishTool(Tool):
    """
    Skipfish is an active web application security reconnaissance tool. This class integrate it with aucote.

    """
    async def call(self, *args, **kwargs):
        if self.port.is_ipv6:
            log.warning("Skipfish doesn't support ipv6 scanning")
            return
        self.context.add_task(SkipfishScanTask(context=self.context, port=self.port, scan=self.scan,
                                               exploits=[self.aucote.exploits.find('skipfish', 'skipfish')]))
