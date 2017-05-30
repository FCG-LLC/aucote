"""
Contains all tasks related to the WhatWeb tool

"""
from tools.common.command_task import CommandTask
from tools.what_web.base import WhatWebBase


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
