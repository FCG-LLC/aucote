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
            'services': ['ssh', 'vnc'],
            'mapper': {
                'test': 'ssh'
            },
            'without-login': 'vnc'
        }

        self.exploits = [self.exploit, self.exploit2]

        self.port = MagicMock()
        self.port.service_name = 'test'
        self.port_nologin = MagicMock()
        self.port_nologin.service_name = 'vnc'

        self.executor = MagicMock()
        self.hydra_tool = HydraTool(executor=self.executor, exploits=self.exploits, port=self.port, config=self.config)
        self.hydra_tool_without_login = HydraTool(executor=self.executor, exploits=self.exploits, port=self.port_nologin,
                                                  config=self.config)

    @patch('tools.hydra.tool.HydraScriptTask')
    @patch('tools.hydra.tool.cfg.get', MagicMock(return_value=MagicMock(cfg=[])))
    def test_call(self, hydra_task_mock):

        self.hydra_tool()
        hydra_task_mock.assert_called_once_with(executor=self.executor, service='ssh', port=self.port, login=True)

    @patch('tools.hydra.tool.HydraScriptTask')
    @patch('tools.hydra.tool.cfg.get', MagicMock(return_value=MagicMock(cfg=[])))
    def test_call_without_login(self, hydra_task_mock):
        self.hydra_tool_without_login()
        hydra_task_mock.assert_called_once_with(executor=self.executor, service='vnc', port=self.port_nologin,
                                                login=False)

    def test_non_implemented_service(self):
        self.config['mapper']['test'] = 'test'
        HydraTool(port=MagicMock(), exploits=MagicMock(), executor=self.executor, config=self.config)()
        self.assertEqual(self.executor.add_task.call_count, 0)

    @patch('tools.hydra.tool.cfg.get', MagicMock(return_value=MagicMock(cfg=['test'])))
    @patch('tools.hydra.tool.HydraScriptTask')
    def test_disabled_service(self, hydra_task_mock):
        self.hydra_tool()
        self.assertEqual(self.executor.add_task.call_count, 0)

    def tearDown(self):
        self.executor.reset_mock()