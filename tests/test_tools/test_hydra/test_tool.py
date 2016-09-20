import ipaddress
from unittest import TestCase
from unittest.mock import patch, MagicMock

from fixtures.exploits import Exploit
from structs import RiskLevel, Port, Scan, Node, TransportProtocol
from tools.hydra.tool import HydraTool
from utils.storage import Storage


# @patch('tools.base.Storage', MagicMock())
class HydraToolTest(TestCase):

    def setUp(self):
        self.exploit = Exploit(name='hydra', app='hydra', risk_level=RiskLevel.NONE)
        self.exploit2 = Exploit(name='hydra', app='hydra', risk_level=RiskLevel.HIGH)

        self.config = {
            'services': ['ssh', 'vnc'],
            'mapper': {
                'test': 'ssh'
            },
            'without-login': 'vnc'
        }

        self.exploits = [self.exploit, self.exploit2]

        self.port = Port(service_name='test', node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1), number=16,
                         transport_protocol=TransportProtocol.UDP)
        self.port.scan = Scan(start=14, end=12)

        self.port_no_login = Port(service_name='vnc', node=Node(ip=ipaddress.ip_address('127.0.0.1'), node_id=1),
                                  number=16, transport_protocol=TransportProtocol.UDP)
        self.port_no_login.scan = Scan(start=14, end=12)

        self.executor = MagicMock()
        self.executor.storage = Storage(":memory:")
        self.hydra_tool = HydraTool(executor=self.executor, exploits=self.exploits, port=self.port, config=self.config)
        self.hydra_tool_without_login = HydraTool(executor=self.executor, exploits=self.exploits,
                                                  port=self.port_no_login, config=self.config)

    @patch('tools.hydra.tool.HydraScriptTask')
    @patch('tools.hydra.tool.cfg.get', MagicMock(return_value=MagicMock(cfg=[])))
    def test_call(self, hydra_task_mock):
        self.hydra_tool()

        hydra_task_mock.assert_called_once_with(executor=self.executor, service='ssh', port=self.port, login=True)

    @patch('tools.hydra.tool.HydraScriptTask')
    @patch('tools.hydra.tool.cfg.get', MagicMock(return_value=MagicMock(cfg=[])))
    def test_call_without_login(self, hydra_task_mock):
        self.hydra_tool_without_login()

        hydra_task_mock.assert_called_once_with(executor=self.executor, service='vnc', port=self.port_no_login,
                                                login=False)

    def test_non_implemented_service(self):
        self.config['mapper']['test'] = 'test'
        HydraTool(port=MagicMock(), exploits=MagicMock(), executor=self.executor, config=self.config)()

        result = self.executor.add_task.called

        self.assertFalse(result)

    @patch('tools.hydra.tool.cfg.get', MagicMock(return_value=MagicMock(cfg=['test'])))
    def test_disabled_service(self):
        self.hydra_tool()

        result = self.executor.add_task.called

        self.assertFalse(result)

    def tearDown(self):
        self.executor.reset_mock()