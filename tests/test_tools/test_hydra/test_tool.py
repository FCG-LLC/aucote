from unittest import TestCase
from unittest.mock import patch, MagicMock

from fixtures.exploits import Exploit
from structs import RiskLevel
from tools.hydra.tool import HydraTool


class HydraToolTest(TestCase):
    def setUp(self):
        self.exploit = Exploit()
        self.exploit.name = 'hydra'
        self.exploit.risk_level = RiskLevel.NONE

        self.exploit2 = Exploit()
        self.exploit2.name = 'hydra'
        self.exploit2.risk_level = RiskLevel.HIGH

        self.config = {
            'services': ['ssh'],
            'mapper': {
                'test': 'ssh'
            }
        }

        self.exploits = [self.exploit, self.exploit2]
        self.port = MagicMock()
        self.port.service_name = 'test'
        self.executor = MagicMock()
        self.nmap_tool = HydraTool(executor=self.executor, exploits=self.exploits, port=self.port, config=self.config)

    @patch('tools.hydra.tool.HydraScriptTask')
    def test_call(self, hydra_task_mock):

        self.nmap_tool()
        hydra_task_mock.assert_called_once_with(executor=self.executor, service='ssh', port=self.port)

    def test_non_implemented_service(self):
        executor = MagicMock()
        self.config['mapper']['test'] = 'test'
        HydraTool(port=MagicMock(), exploits=MagicMock(), executor=executor, config=self.config)()
        self.assertEqual(executor.add_task.call_count, 0)



