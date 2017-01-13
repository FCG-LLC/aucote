from unittest import TestCase
from unittest.mock import MagicMock

from inotify.calls import InotifyError
from inotify.constants import IN_IGNORED, IN_MODIFY, IN_DELETE_SELF

from utils.watchdog_task import WatchdogTask

class WatchdogTaskTest(TestCase):

    def setUp(self):
        self.file = "test_file"
        self.action = MagicMock()
        self.task = WatchdogTask(file=self.file, action=self.action, executor=MagicMock())

    def test_call_is_modified(self):
        side_effects = ((
            (MagicMock(mask=IN_MODIFY), ["IN_MODIFY"], None, self.file),
            (MagicMock(mask=IN_DELETE_SELF), ["IN_DELETE_SELF"], None, self.file),
        ), )
        self.task.notifier.event_gen = MagicMock(side_effect=side_effects)
        self.task.notifier.add_watch = MagicMock()
        self.task.notifier.remove_watch = MagicMock()

        self.task()

        self.task.notifier.add_watch.called_once_with(self.file)
        self.assertEqual(self.task.action.call_count, 2)
        self.task.notifier.remove_watch.called_once_with()

    def test_call_is_ignored(self):
        side_effects = ((
            (MagicMock(mask=IN_IGNORED), ["IN_IGNORED"], None, self.file),
        ), )
        self.task.notifier.event_gen = MagicMock(side_effect=side_effects)
        self.task.notifier.add_watch = MagicMock()
        self.task.notifier.remove_watch = MagicMock()

        self.task()

        self.assertEqual(self.task.notifier.add_watch.call_count, 2)
        self.task.notifier.remove_watch.called_once_with()

    def test_exception(self):
        self.task.notifier.add_watch = MagicMock()
        self.task.notifier.event_gen = MagicMock(side_effect=InotifyError("test"))
        self.task.notifier.remove_watch = MagicMock()

        self.task()

    def test_stop(self):
        self.task.notifier.remove_watch = MagicMock()
        self.assertRaises(InotifyError, self.task.stop)
        self.task.notifier.remove_watch.assert_Caaled_once_with(self.task.file)
