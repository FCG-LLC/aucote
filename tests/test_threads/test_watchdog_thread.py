from unittest import TestCase
from unittest.mock import MagicMock

from inotify.calls import InotifyError
from inotify.constants import IN_IGNORED, IN_MODIFY, IN_DELETE_SELF

from threads.watchdog_thread import WatchdogThread


class WatchdogThreadTest(TestCase):

    def setUp(self):
        self.file = "test_file"
        self.action = MagicMock()
        self.thread = WatchdogThread(file=self.file, action=self.action)

    def test_call_is_modified(self):
        side_effects = ((
            (MagicMock(mask=IN_MODIFY), ["IN_MODIFY"], None, self.file),
            (MagicMock(mask=IN_DELETE_SELF), ["IN_DELETE_SELF"], None, self.file),
        ), )
        self.thread.notifier.event_gen = MagicMock(side_effect=side_effects)
        self.thread.notifier.add_watch = MagicMock()
        self.thread.notifier.remove_watch = MagicMock()

        self.thread.run()

        self.thread.notifier.add_watch.called_once_with(self.file)
        self.assertEqual(self.thread.action.call_count, 2)
        self.thread.notifier.remove_watch.called_once_with()

    def test_call_is_ignored(self):
        self.thread._finish = True
        side_effects = ((
            (MagicMock(mask=IN_IGNORED), ["IN_IGNORED"], None, self.file),
            None
        ), )
        self.thread.notifier.event_gen = MagicMock(side_effect=side_effects)
        self.thread.notifier.add_watch = MagicMock()
        self.thread.notifier.remove_watch = MagicMock(side_effect=InotifyError("test"))

        self.thread.run()

        self.assertEqual(self.thread.notifier.add_watch.call_count, 2)
        self.thread.notifier.remove_watch.called_once_with()

    def test_exception(self):
        self.thread.notifier.add_watch = MagicMock()
        self.thread.notifier.event_gen = MagicMock(side_effect=InotifyError("test"))
        self.thread.notifier.remove_watch = MagicMock()

        self.thread.run()

    def test_stop(self):
        self.thread.notifier.remove_watch = MagicMock()
        self.thread._finish = False
        self.thread.stop()
        self.assertTrue(self.thread._finish)
