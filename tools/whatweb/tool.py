"""
Provides WhatWeb tool

"""
from tools.base import Tool
from tools.whatweb.tasks import WhatWebTask


class WhatWebTool(Tool):
    """
    WhatWeb is a web application detector. Provides over 1000 plugins for different frameworks and technologies

    """
    async def call(self):
        self.context.add_task(WhatWebTask(aucote=self.aucote, port=self.port, scan=self._scan,
                                          exploits=[self.aucote.exploits.find('whatweb', 'whatweb')]))
