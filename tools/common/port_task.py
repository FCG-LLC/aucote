from utils.task import Task


class PortTask(Task):
    def __init__(self, port, exploit, *args, **kwargs):
        """
        Initialize variables

        Args:
            port (Port):
            exploit (Exploit):
            *args:
            **kwargs:

        """
        super().__init__(*args, **kwargs)
        self._port = port

        if isinstance(exploit, (list, set)):
            self.current_exploits = exploit
            self.exploit = None
        else:
            self.exploit = exploit
            self.current_exploits = [exploit]