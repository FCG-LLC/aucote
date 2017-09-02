from structs import Vulnerability
from tools.common.command_task import CommandTask


class Enum4linuxTask(CommandTask):
    def get_vulnerabilities(self, results):
        return Vulnerability(exploit=self.exploit, output=str(results), port=self.port)

    def __init__(self, username, password, domain, *args, **kwargs):
        self.username = username
        self.password = password
        self.domain = domain
        super(Enum4linuxTask, self).__init__(*args, **kwargs)

    def prepare_args(self):
        """
        Prepare aguments for command execution

        Returns:
            list

        """
        return ['-u', self.username, '-p', self.password, '-w', self.domain, str(self.port.node.ip)]
