"""
Test main aucote file
"""
from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock, PropertyMock, mock_open

from aucote import main, run_scan, run_service, run_syncdb
from utils.exceptions import NmapUnsupported, TopdisConnectionException


@patch('aucote_cfg.cfg.get', Mock(return_value=""))
@patch('aucote_cfg.cfg.load', Mock(return_value=""))
@patch('utils.log.config', Mock(return_value=""))
class AucoteTest(TestCase):
    @patch('builtins.open', mock_open())
    def test_main_scan(self):
        args = PropertyMock()
        args.configure_mock(cmd='scan')

        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.run_scan') as mock:
                main()

        self.assertEqual(mock.call_count, 1)

    @patch('fixtures.exploits.Exploits.read', MagicMock(side_effect=NmapUnsupported))
    @patch('builtins.open', mock_open())
    def test_main_exploits_exception(self):
        args = PropertyMock()
        args.configure_mock(cmd='scan')

        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.run_scan'):
                self.assertRaises(SystemExit, main)

    @patch('builtins.open', mock_open())
    def test_main_service(self):
        args = PropertyMock()
        args.configure_mock(cmd='service')
        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            with patch('aucote.run_service') as mock:
                main()

        self.assertEqual(mock.call_count, 1)

    @patch('builtins.open', mock_open())
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
        run_scan(exploits=MagicMock())
        self.assertEqual(mock_executor.call_count, 1)

    @patch('aucote.run_scan', MagicMock())
    @patch('aucote.parse_period')
    @patch('sched.scheduler.run')
    @patch('sched.scheduler.enter')
    def test_service(self, mock_sched_enter, mock_sched_run, mock_parse_period):
        mock_sched_run.side_effect = self.check_service # NotImplementedError('test')
        self._mock = mock_sched_run
        self.assertRaises(NotImplementedError, run_service, MagicMock())
        self.assertEqual(mock_sched_enter.call_count, 3)
        self.assertEqual(mock_sched_run.call_count, 3)

    def check_service(self):
        if self._mock.call_count == 3:
            raise NotImplementedError


    @patch('utils.kudu_queue.KuduQueue.__exit__', MagicMock(return_value=False))
    @patch('utils.kudu_queue.KuduQueue.__enter__', MagicMock(return_value=MagicMock()))
    @patch('database.serializer.Serializer.serialize_exploit')
    def test_syncdb(self, mock_serializer):
        run_syncdb(range(5))
        self.assertEqual(mock_serializer.call_count, 5)

    @patch('utils.kudu_queue.KuduQueue.__exit__', MagicMock(return_value=False))
    @patch('utils.kudu_queue.KuduQueue.__enter__', MagicMock(return_value=False))
    @patch('scans.executor.Executor.__init__', MagicMock(side_effect=TopdisConnectionException, return_value=None))
    @patch('scans.executor.Executor.run')
    def test_scan_with_exception(self, mock_executor):
        run_scan(exploits=MagicMock())
        self.assertEqual(mock_executor.call_count, 0)