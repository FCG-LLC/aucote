import ipaddress
from unittest.mock import patch, MagicMock

from tornado.testing import gen_test, AsyncTestCase

from fixtures.exploits import Exploit, RiskLevel
from structs import Port, Scan, Node, TransportProtocol, ScanContext
from tools.hydra.tool import HydraTool
from utils import Config


class HydraToolTest(AsyncTestCase):

    def setUp(self):
        super(HydraToolTest, self).setUp()
        self.exploit = Exploit(exploit_id=1, name='hydra', app='hydra', risk_level=RiskLevel.NONE)
        self.exploit2 = Exploit(exploit_id=2, name='hydra', app='hydra', risk_level=RiskLevel.HIGH)

        self.config = {
            'services': ['ssh', 'vnc'],
            'mapper': {
                'test': 'ssh'
            },
            'without-login': 'vnc'
        }

        self.exploits = [self.exploit, self.exploit2]

        self.node = Node(node_id=1, ip=ipaddress.ip_address('127.0.0.1'))

        self.port = Port(number=12, transport_protocol=TransportProtocol.TCP, node=self.node)
        self.port.protocol = 'test'
        self.port.scan = Scan(start=14)

        self.port_no_login = Port(number=12, transport_protocol=TransportProtocol.TCP, node=self.node)
        self.port_no_login.protocol = 'vnc'
        self.port_no_login.scan = Scan(start=14)

        self.aucote = MagicMock()
        self.context = ScanContext(aucote=self.aucote, scanner=None)
        self.scan = Scan()
        self.hydra_tool = HydraTool(context=self.context, exploits=self.exploits, port=self.port, config=self.config,
                                    scan=self.scan,)
        self.hydra_tool_without_login = HydraTool(context=self.context, exploits=self.exploits, scan=self.scan,
                                                  port=self.port_no_login, config=self.config)

    @patch('tools.hydra.tool.HydraScriptTask')
    @patch('tools.hydra.tool.cfg.get', MagicMock(return_value=MagicMock(cfg=[])))
    @gen_test
    async def test_call(self, hydra_task_mock):
        await self.hydra_tool()

        hydra_task_mock.assert_called_once_with(context=self.context, service='ssh', port=self.port, login=True,
                                                exploits=[self.aucote.exploits.find.return_value], scan=self.scan,)

    @patch('tools.hydra.tool.HydraScriptTask')
    @patch('tools.hydra.tool.cfg.get', MagicMock(return_value=MagicMock(cfg=[])))
    @gen_test
    async def test_call_without_login(self, hydra_task_mock):
        await self.hydra_tool_without_login()

        hydra_task_mock.assert_called_once_with(context=self.context, service='vnc', port=self.port_no_login,
                                                login=False, exploits=[self.aucote.exploits.find.return_value],
                                                scan=self.scan,)

    @gen_test
    async def test_non_implemented_service(self):
        self.config['mapper']['test'] = 'test'
        await HydraTool(port=MagicMock(), exploits=MagicMock(), context=self.context, config=self.config,
                        scan=self.scan)()

        result = self.aucote.add_task.called

        self.assertFalse(result)

    @patch('tools.hydra.tool.cfg.get', MagicMock(return_value=Config(['test'])))
    @gen_test
    async def test_disabled_service(self):
        await self.hydra_tool()

        result = self.aucote.add_task.called

        self.assertFalse(result)

    def tearDown(self):
        self.aucote.reset_mock()