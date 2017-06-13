"""
Provides WhatWeb tool

"""
from tools.base import Tool
from tools.whatweb.tasks import WhatWebTask


class WhatWebTool(Tool):
    """
    WhatWeb is a web application detector. Provides over 1000 plugins for different frameworks and technologies

    """
    def call(self):
        self.aucote.add_task(WhatWebTask(aucote=self.aucote, port=self.port,
                                              exploits=[self.aucote.exploits.find('whatweb', 'whatweb')]))
