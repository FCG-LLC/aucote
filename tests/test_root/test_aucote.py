"""
Test main aucote file
"""
from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock, PropertyMock, mock_open

from aucote import main, Aucote
from utils.exceptions import NmapUnsupported, TopdisConnectionException
from utils.storage import Storage


@patch('aucote_cfg.cfg.get', Mock(return_value=":memory:"))
@patch('aucote_cfg.cfg.load', Mock(return_value=""))
@patch('utils.log.config', Mock(return_value=""))
class AucoteTest(TestCase):
    def setUp(self):
        storage = Storage(":memory:")
        storage.connect()
        self.aucote = Aucote(exploits=MagicMock(), storage=storage, kudu_queue=MagicMock())

    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl', MagicMock())
    def test_main_scan(self):
        args = PropertyMock()
        args.configure_mock(cmd='scan')

        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.Aucote.run_scan') as mock:
                main()

        self.assertEqual(mock.call_count, 1)

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
    def test_main_service(self):
        args = PropertyMock()
        args.configure_mock(cmd='service')
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.Aucote.run_service') as mock:
                main()

        self.assertEqual(mock.call_count, 1)

    @patch('builtins.open', mock_open())
    @patch('aucote.KuduQueue', MagicMock())
    @patch('aucote.fcntl', MagicMock())
    def test_main_syncdb(self):
        args = PropertyMock()
        args.configure_mock(cmd='syncdb')
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.Aucote.run_syncdb') as mock:
                main()

        self.assertEqual(mock.call_count, 1)

    @patch('scans.executor.Executor.__init__', MagicMock(return_value=None))
    @patch('aucote.ScanTask')
    def test_scan(self, mock_scan_tasks):
        self.aucote._thread_pool = MagicMock()
        self.aucote._storage = MagicMock()
        self.aucote._kudu_queue = MagicMock()

        self.aucote.run_scan()
        result = mock_scan_tasks.call_args[1]
        expected = {
            'executor': self.aucote,
            'nodes': None
        }

        self.assertEqual(mock_scan_tasks.call_count, 1)
        self.assertDictEqual(result, expected)
        self.assertTrue(self.aucote.storage.clear_scan_details.called)
        self.aucote._thread_pool.start.called_once_with()
        self.aucote._thread_pool.join.called_once_with()
        self.aucote._thread_pool.stop.called_once_with()

    @patch('aucote.Aucote.run_scan', MagicMock())
    @patch('aucote.parse_period')
    @patch('sched.scheduler.run')
    @patch('sched.scheduler.enter')
    @patch('aucote.KuduQueue', MagicMock())
    def test_service(self, mock_sched_enter, mock_sched_run, mock_parse_period):
        mock_sched_run.side_effect = self.check_service # NotImplementedError('test')
        self._mock = mock_sched_run
        self.assertRaises(NotImplementedError, self.aucote.run_service)
        self.assertEqual(mock_sched_enter.call_count, 3)
        self.assertEqual(mock_sched_run.call_count, 3)

    def check_service(self):
        if self._mock.call_count == 3:
            raise NotImplementedError

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
            with patch('aucote.Aucote.run_service'):
                self.assertRaises(SystemExit, main)

    def test_init(self):
        exploits = MagicMock()
        kudu_queue = MagicMock()
        storage = MagicMock()

        aucote = Aucote(exploits=exploits, kudu_queue=kudu_queue, storage=storage)

        self.assertEqual(aucote.storage, storage)
        self.assertTrue(storage.create_tables.called)
        self.assertEqual(aucote.kudu_queue, kudu_queue)
        self.assertEqual(aucote.storage, storage)