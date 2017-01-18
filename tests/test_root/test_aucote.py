"""
Test main aucote file
"""
from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock, PropertyMock, mock_open

import signal

from aucote import main, Aucote
from utils.exceptions import NmapUnsupported, TopdisConnectionException, FinishThread
from utils.storage import Storage


@patch('aucote_cfg.cfg.get', Mock(return_value=":memory:"))
@patch('aucote_cfg.cfg.load', Mock(return_value=""))
@patch('utils.log.config', Mock(return_value=""))
@patch('aucote.os.remove', MagicMock(side_effect=FileNotFoundError()))
class AucoteTest(TestCase):
    def setUp(self):
        self.aucote = Aucote(exploits=MagicMock(), kudu_queue=MagicMock(), tools_config=MagicMock())
        self.aucote.storage_thread = MagicMock()

    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl', MagicMock())
    @patch('aucote.Aucote')
    def test_main_scan(self, mock_aucote):
        args = PropertyMock()
        args.configure_mock(cmd='scan')

        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            main()

        self.assertEqual(mock_aucote.return_value.run_scan.call_count, 1)

    @patch('fixtures.exploits.Exploits.read', MagicMock(side_effect=NmapUnsupported))
    @patch('builtins.open', mock_open())
    @patch('aucote.fcntl', MagicMock())
    def test_main_exploits_exception(self):
        args = PropertyMock()
        args.configure_mock(cmd='scan')

        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.Aucote.run_scan'):
                self.assertRaises(SystemExit, main)

    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl', MagicMock())
    @patch('aucote.cfg')
    @patch('aucote.Aucote')
    def test_main_service(self, mock_aucote, mock_cfg):
        args = PropertyMock()
        args.configure_mock(cmd='service')
        mock_aucote.return_value.run_scan.side_effect = (None, SystemExit(), )
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            self.assertRaises(SystemExit, main)

        mock_aucote.return_value.run_scan.assert_called_any_with()
        self.assertEqual(mock_aucote.return_value.run_scan.call_count, 2)
        mock_cfg.reload.assert_called_once_with(mock_cfg.get.return_value)

    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl', MagicMock())
    @patch('aucote.Aucote')
    def test_main_syncdb(self, mock_aucote):
        args = PropertyMock()
        args.configure_mock(cmd='syncdb')
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            main()

        self.assertEqual(mock_aucote.return_value.run_syncdb.call_count, 1)

    @patch('scans.executor.Executor.__init__', MagicMock(return_value=None))
    @patch('aucote.StorageThread')
    @patch('aucote.ScanTask')
    def test_scan(self, mock_scan_tasks, mock_storage_task):
        self.aucote._thread_pool = MagicMock()
        self.aucote._storage = MagicMock()
        self.aucote._kudu_queue = MagicMock()

        self.aucote.run_scan(as_service=False)
        result = mock_scan_tasks.call_args[1]
        expected = {
            'executor': self.aucote,
            'as_service': False
        }

        self.assertEqual(mock_scan_tasks.call_count, 1)
        self.assertEqual(mock_storage_task.call_count, 1)
        self.assertDictEqual(result, expected)
        self.aucote._thread_pool.start.called_once_with()
        self.aucote._thread_pool.join.called_once_with()
        self.aucote._thread_pool.stop.called_once_with()

    @patch('scans.executor.Executor.__init__', MagicMock(return_value=None))
    @patch('aucote.StorageThread')
    @patch('aucote.WatchdogThread')
    @patch('aucote.ScanTask')
    def test_service(self, mock_scan_tasks, mock_watchdog, mock_storage_task):
        self.aucote._thread_pool = MagicMock()
        self.aucote._storage = MagicMock()
        self.aucote._kudu_queue = MagicMock()

        self.aucote.run_scan(as_service=True)
        result = mock_scan_tasks.call_args[1]
        expected = {
            'executor': self.aucote,
            'as_service': True
        }

        self.assertEqual(mock_scan_tasks.call_count, 1)
        self.assertEqual(mock_storage_task.call_count, 1)
        self.assertEqual(mock_watchdog.call_count, 1)
        self.assertDictEqual(result, expected)
        self.aucote._thread_pool.start.called_once_with()
        self.aucote._thread_pool.join.called_once_with()
        self.aucote._thread_pool.stop.called_once_with()

    @patch('utils.kudu_queue.KuduQueue.__exit__', MagicMock(return_value=False))
    @patch('utils.kudu_queue.KuduQueue.__enter__', MagicMock(return_value=MagicMock()))
    @patch('database.serializer.Serializer.serialize_exploit')
    @patch('aucote.KuduQueue', MagicMock())
    def test_syncdb(self, mock_serializer):
        self.aucote.exploits = range(5)
        self.aucote.run_syncdb()
        self.assertEqual(mock_serializer.call_count, 5)

    @patch('utils.kudu_queue.KuduQueue.__exit__', MagicMock(return_value=False))
    @patch('utils.kudu_queue.KuduQueue.__enter__', MagicMock(return_value=False))
    @patch('aucote.ScanTask.__init__', MagicMock(side_effect=TopdisConnectionException, return_value=None))
    @patch('aucote.StorageThread', MagicMock())
    @patch('scans.scan_task.Executor')
    def test_scan_with_exception(self, mock_executor):
        self.aucote.run_scan()
        self.assertEqual(mock_executor.call_count, 0)

    def test_add_task(self):
        self.aucote._thread_pool = MagicMock()
        data = MagicMock()

        self.aucote.add_task(data)
        self.aucote._thread_pool.add_task.called_once_with(data)

    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl')
    def test_aucote_run_already(self, mock_fcntl):
        mock_fcntl.lockf = MagicMock(side_effect=IOError())
        args = PropertyMock()
        args.configure_mock(cmd='service')
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.Aucote.run_scan'):
                self.assertRaises(SystemExit, main)

    @patch('aucote.Aucote.load_tools')
    def test_init(self, mock_loader):
        exploits = MagicMock()
        kudu_queue = MagicMock()
        cfg = MagicMock()

        aucote = Aucote(exploits=exploits, kudu_queue=kudu_queue, tools_config=cfg)

        self.assertEqual(aucote.storage, None)
        self.assertEqual(aucote.kudu_queue, kudu_queue)
        mock_loader.called_once_With(cfg)

    def test_signal_handling(self):
        self.assertRaises(SystemExit, self.aucote.signal_handler, 2, MagicMock())

    def test_storage_setter_default(self):
        self.aucote._storage = None
        expected = MagicMock()
        self.aucote.storage = expected

        self.assertEqual(self.aucote.storage, expected)

    def test_storage_setter_none(self):
        self.aucote._storage = MagicMock()
        expected = None
        self.aucote.storage = expected

        self.assertEqual(self.aucote.storage, expected)

    def test_storage_setter_set_already(self):
        expected = MagicMock()
        self.aucote._storage = expected
        self.aucote.storage = MagicMock()

        self.assertEqual(self.aucote.storage, expected)

    def test_load_tools(self):
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

    @patch('aucote.cfg')
    def test_reload_config(self, mock_cfg):
        filename = 'test_filename'
        self.aucote.scan_task = MagicMock()

        self.aucote.reload_config(filename)

        mock_cfg.assert_Called_once_with(filename)
        self.aucote.scan_task.reload_config.assert_called_once_with()

    def test_graceful_stop(self):
        self.aucote.scan_task = MagicMock()
        self.aucote.watch_thread = MagicMock()
        self.aucote.graceful_stop()
        self.aucote.watch_thread.stop.assert_called_once_with()
        self.aucote.scan_task.disable_scan.assert_called_once_with()

    @patch('aucote.os.getpid', MagicMock(return_value=1337))
    @patch('aucote.os.kill')
    def test_kill(self, mock_kill):
        self.aucote.kill()
        mock_kill.assert_called_once_with(1337, signal.SIGTERM)

    def test_unfinished_tasks(self):
        self.assertEqual(self.aucote.unfinished_tasks, self.aucote.thread_pool.unfinished_tasks)
