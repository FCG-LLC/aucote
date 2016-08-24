"""
Test main aucote file
"""
from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock, PropertyMock, mock_open

from aucote import main, run_scan, run_service, run_syncdb


@patch('aucote_cfg.cfg.get', Mock(return_value=""))
@patch('aucote_cfg.cfg.load', Mock(return_value=""))
@patch('utils.log.config', Mock(return_value=""))
class AucoteTest(TestCase):
    def test_main_scan(self):
        args = PropertyMock()
        args.configure_mock(cmd='scan')

        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.run_scan') as mock:
                main()

        self.assertEqual(mock.call_count, 1)

    def test_main_service(self):
        args = PropertyMock()
        args.configure_mock(cmd='service')
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.run_service') as mock:
                main()

        self.assertEqual(mock.call_count, 1)

    def test_main_syncdb(self):
        args = PropertyMock()
        args.configure_mock(cmd='syncdb')
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.run_syncdb') as mock:
                main()

        self.assertEqual(mock.call_count, 1)

    @patch('utils.kudu_queue.KuduQueue.__exit__', MagicMock(return_value=False))
    @patch('utils.kudu_queue.KuduQueue.__enter__', MagicMock(return_value=False))
    @patch('scans.executor.Executor.__init__', MagicMock(return_value=None))
    @patch('scans.executor.Executor.run')
    def test_scan(self, mock_executor):
        run_scan()
        self.assertEqual(mock_executor.call_count, 1)

    @patch('aucote.run_scan', MagicMock())
    @patch('utils.time.parse_period', MagicMock())
    @patch('sched.scheduler.run')
    @patch('sched.scheduler.enter')
    def test_service(self, mock_sched_enter, mock_sched_run):
        mock_sched_run.side_effect = NotImplementedError('test')
        self.assertRaises(NotImplementedError, run_service)
        self.assertEqual(mock_sched_enter.call_count, 1)
        self.assertEqual(mock_sched_run.call_count, 1)

    @patch('utils.kudu_queue.KuduQueue.__exit__', MagicMock(return_value=False))
    @patch('utils.kudu_queue.KuduQueue.__enter__', MagicMock(return_value=MagicMock()))
    @patch('fixtures.exploits.read_exploits', MagicMock(return_value=range(5)))
    @patch('database.serializer.Serializer.serialize_exploit')
    def test_syncdb(self, mock_serializer):
        run_syncdb()
        self.assertEqual(mock_serializer.call_count, 5)
