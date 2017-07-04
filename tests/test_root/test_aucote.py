"""
Test main aucote file
"""
from unittest.mock import patch, Mock, MagicMock, PropertyMock, mock_open, call

import sys
from tornado.concurrent import Future
from tornado.testing import AsyncTestCase, gen_test

from aucote import main, Aucote
from utils import Config
from utils.exceptions import NmapUnsupported


@patch('aucote_cfg.cfg.load', Mock(return_value=""))
@patch('utils.log.config', Mock(return_value=""))
@patch('aucote.os.remove', MagicMock(side_effect=FileNotFoundError()))
class AucoteTest(AsyncTestCase):
    @patch('aucote.Storage')
    @patch('aucote.cfg', new_callable=Config)
    @patch('aucote.AsyncTaskManager', MagicMock())
    def setUp(self, cfg, mock_storage):
        super(AucoteTest, self).setUp()
        self.storage = mock_storage
        self.cfg = {
            'service': {
                'scans': {
                    'threads': 30,
                    'storage': 'test_storage',
                    'parallel_tasks': 30
                },
                'api': {
                    'v1': {
                        'host': None,
                        'port': None
                    }
                }
            },
            'kuduworker': {
                'queue': {
                    'address': None
                }
            },
            'pid_file': None,
            'fixtures': {
                'exploits': {
                    'filename': None
                }
            },
            'config_filename': 'test'
        }
        cfg._cfg = self.cfg
        self.aucote = Aucote(exploits=MagicMock(), kudu_queue=MagicMock(), tools_config=MagicMock())
        self.aucote.ioloop = MagicMock()
        self.aucote._storage_thread = MagicMock()

        future = Future()
        future.set_result(MagicMock())
        self.aucote.task_manager.shutdown_condition.wait.return_value = future

        self.aucote._scan_task = MagicMock()
        self.scan_task_run = MagicMock()
        scan_task_future = Future()
        scan_task_future.set_result(self.scan_task_run)
        self.aucote._scan_task.run.return_value = scan_task_future

    @patch('aucote.cfg_load')
    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl', MagicMock())
    @patch('aucote.Aucote')
    @patch('aucote.cfg', new_callable=Config)
    @gen_test
    async def test_main_scan(self, cfg, mock_aucote, mock_cfg_load):
        mock_cfg_load.return_value = Future()
        mock_cfg_load.return_value.set_result(True)
        cfg._cfg = self.cfg
        args = PropertyMock()
        args.configure_mock(cmd='scan')
        future = Future()
        future.set_result(MagicMock())
        mock_aucote().run_scan.return_value = future

        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            await main()

        self.assertEqual(mock_aucote.return_value.run_scan.call_count, 1)

    @patch('aucote.cfg_load')
    @patch('fixtures.exploits.Exploits.read', MagicMock(side_effect=NmapUnsupported))
    @patch('builtins.open', mock_open())
    @patch('aucote.fcntl', MagicMock())
    @gen_test
    async def test_main_exploits_exception(self, mock_cfg_load):
        mock_cfg_load.return_value = Future()
        mock_cfg_load.return_value.set_result(True)
        args = PropertyMock()
        args.configure_mock(cmd='scan')

        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.Aucote.run_scan'):
                with self.assertRaises(SystemExit):
                    await main()

    @patch('aucote.cfg_load')
    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl', MagicMock())
    @patch('aucote.cfg')
    @patch('aucote.Aucote')
    @gen_test
    async def test_main_service(self, mock_aucote, mock_cfg, mock_cfg_load):
        mock_cfg_load.return_value = Future()
        mock_cfg_load.return_value.set_result(True)
        args = PropertyMock()
        args.configure_mock(cmd='service')
        future = Future()
        future.set_result(MagicMock())
        mock_aucote.return_value.run_scan.side_effect = (future, SystemExit(), )
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with self.assertRaises(SystemExit):
                await main()

        mock_aucote.return_value.run_scan.assert_any_call()
        self.assertEqual(mock_aucote.return_value.run_scan.call_count, 2)
        mock_cfg.reload.assert_called_once_with(mock_cfg.__getitem__.return_value)

    @patch('aucote.cfg_load')
    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl', MagicMock())
    @patch('aucote.Aucote')
    @patch('aucote.cfg', new_callable=Config)
    @gen_test
    async def test_main_syncdb(self, cfg, mock_aucote, mock_cfg_load):
        mock_cfg_load.return_value = Future()
        mock_cfg_load.return_value.set_result(True)
        cfg._cfg = self.cfg
        args = PropertyMock()
        args.configure_mock(cmd='syncdb')
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            await main()

        self.assertEqual(mock_aucote.return_value.run_syncdb.call_count, 1)

    @patch('scans.executor.Executor.__init__', MagicMock(return_value=None))
    @patch('aucote.ToolsScanner')
    @patch('aucote.UDPScanner')
    @patch('aucote.TCPScanner')
    @patch('aucote.Storage')
    @patch('aucote.WebServer', MagicMock())
    @patch('aucote.IOLoop', MagicMock())
    @patch('aucote.cfg', new_callable=Config)
    @gen_test
    async def test_service(self, cfg, mock_storage_task, tcp_scanner, udp_scanner, tools_scanner):
        cfg._cfg = self.cfg
        self.aucote._storage = MagicMock()
        self.aucote._kudu_queue = MagicMock()
        self.aucote.task_manager = MagicMock()
        self.aucote.task_manager.shutdown_condition.wait.return_value = Future()
        self.aucote.task_manager.shutdown_condition.wait.return_value.set_result(True)

        tcp_scanner.return_value.return_value = Future()
        tcp_scanner.return_value.return_value.set_result(True)

        udp_scanner.return_value.return_value = Future()
        udp_scanner.return_value.return_value.set_result(True)

        tools_scanner.return_value.return_value = Future()
        tools_scanner.return_value.return_value.set_result(True)

        await self.aucote.run_scan(as_service=True)
        self.aucote.task_manager.add_crontab_task.assert_has_calls((call(tcp_scanner(), tcp_scanner()._scan_cron),
                                                                    call(udp_scanner(), udp_scanner()._scan_cron),
                                                                    call(tools_scanner(), tools_scanner()._scan_cron)))

    @patch('scans.executor.Executor.__init__', MagicMock(return_value=None))
    @patch('aucote.UDPScanner')
    @patch('aucote.TCPScanner')
    @patch('aucote.Storage')
    @patch('aucote.WebServer', MagicMock())
    @patch('aucote.IOLoop', MagicMock())
    @patch('aucote.cfg', new_callable=Config)
    @gen_test
    async def test_non_service(self, cfg, mock_storage_task, tcp_scanner, udp_scanner):
        cfg._cfg = self.cfg
        self.aucote._storage = MagicMock()
        self.aucote._kudu_queue = MagicMock()
        self.aucote.task_manager = MagicMock()
        self.aucote.task_manager.shutdown_condition.wait.return_value = Future()
        self.aucote.task_manager.shutdown_condition.wait.return_value.set_result(True)
        self.aucote.task_manager.stop = MagicMock(return_value=Future())
        self.aucote.task_manager.stop.return_value.set_result(True)

        tcp_scanner.return_value.return_value = Future()
        tcp_scanner.return_value.return_value.set_result(True)

        udp_scanner.return_value.return_value = Future()
        udp_scanner.return_value.return_value.set_result(True)

        await self.aucote.run_scan(as_service=False)

        tcp_scanner.assert_called_once_with(aucote=self.aucote, scan_only=False)
        udp_scanner.assert_called_once_with(aucote=self.aucote, scan_only=False)

    @patch('utils.kudu_queue.KuduQueue.__exit__', MagicMock(return_value=False))
    @patch('utils.kudu_queue.KuduQueue.__enter__', MagicMock(return_value=MagicMock()))
    @patch('database.serializer.Serializer.serialize_exploit')
    @patch('aucote.KuduQueue', MagicMock())
    def test_syncdb(self, mock_serializer):
        self.aucote.exploits = range(5)
        self.aucote.run_syncdb()
        self.assertEqual(mock_serializer.call_count, 5)

    @patch('aucote.cfg_load')
    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl')
    @gen_test
    async def test_aucote_run_already(self, mock_fcntl, mock_cfg_load):
        mock_cfg_load.return_value = Future()
        mock_cfg_load.return_value.set_result(True)
        mock_fcntl.lockf = MagicMock(side_effect=IOError())
        args = PropertyMock()
        args.configure_mock(cmd='service')
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.Aucote.run_scan'):
                with self.assertRaises(SystemExit):
                    await main()

    @patch('aucote.Storage')
    @patch('aucote.Aucote.load_tools')
    @patch('aucote.cfg', new_callable=Config)
    @patch('aucote.AsyncTaskManager', MagicMock())
    def test_init(self, cfg, mock_loader, mock_storage):
        cfg._cfg = self.cfg
        exploits = MagicMock()
        kudu_queue = MagicMock()
        cfg = MagicMock()

        aucote = Aucote(exploits=exploits, kudu_queue=kudu_queue, tools_config=cfg)

        self.assertEqual(aucote.kudu_queue, kudu_queue)
        mock_storage.assert_called_once_with(filename='test_storage')
        self.assertEqual(aucote.storage, mock_storage())
        mock_loader.assert_called_once_with(cfg)

    def test_signal_handling(self):
        self.aucote.kill = MagicMock()
        self.aucote.signal_handler(2, None)
        self.aucote.kill.assert_called_once_with()

    @patch('aucote.cfg', new_callable=Config)
    @patch('aucote.Storage', MagicMock())
    def test_load_tools(self, cfg):
        cfg._cfg = self.cfg
        config = {
            'apps': {
                'app1': {
                    'name': MagicMock,
                    'loader': MagicMock(),
                },
                'app2': {
                    'name': MagicMock,
                    'loader': MagicMock(),
                }
            }
        }

        exploits = MagicMock()
        Aucote(exploits=exploits, kudu_queue=MagicMock(), tools_config=config)

        config['apps']['app1']['loader'].assert_called_once_with(config['apps']['app1'], exploits)
        config['apps']['app2']['loader'].assert_called_once_with(config['apps']['app2'], exploits)

    @gen_test
    def test_graceful_stop_signal(self):
        self.aucote._scan_task = MagicMock()

        future_1 = Future()
        future_1.set_result(None)
        self.aucote.task_manager.stop.return_value = future_1

        self.aucote._watch_thread = MagicMock()
        self.aucote.graceful_stop(None, None)

        self.aucote.ioloop.add_callback_from_signal.assert_called_once_with(self.aucote._graceful_stop)

    @gen_test
    async def test_graceful_stop(self):
        future = Future()
        future.set_result(MagicMock())

        future_wait = Future()
        future_wait.set_result(MagicMock())
        self.aucote.task_manager.stop.return_value = future_wait

        await self.aucote._graceful_stop()
        self.aucote.task_manager.stop.assert_called_once_with()

    @patch('aucote.os._exit')
    def test_kill(self, mock_kill):
        self.aucote.kill()
        mock_kill.assert_called_once_with(1)

    def test_unfinished_tasks(self):
        self.assertEqual(self.aucote.unfinished_tasks, self.aucote.task_manager.unfinished_tasks)

    def test_python_version(self):
        self.assertGreaterEqual(sys.version_info, (3, 5))

    def test_add_async_task(self):
        task = MagicMock()
        self.aucote.task_manager.add_task = MagicMock()
        self.aucote.add_async_task(task)
        self.aucote.task_manager.add_task.assert_called_once_with(task)
