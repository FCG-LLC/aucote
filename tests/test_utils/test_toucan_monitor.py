from unittest.mock import MagicMock

from tornado.testing import AsyncTestCase, gen_test

from utils.toucan_monitor import ToucanMonitor


class ToucanMonitorTest(AsyncTestCase):
    def setUp(self):
        super().setUp()
        self.toucan = MagicMock()
        self.toucan_monitor = ToucanMonitor(toucan=self.toucan, ioloop=self.io_loop)

    def test_register(self):
        callback = MagicMock()
        key = 'test.key'
        default = 'default_value'

        self.toucan_monitor.register_toucan_key(key=key, callback=callback, default=default)

        expected = {
            'test.key': {
                'callback': callback,
                'default': default,
                'add_prefix': True
            }
        }

        result = self.toucan_monitor._toucan_keys

        self.assertEqual(result, expected)

    @gen_test
    async def test_polling(self):
        self.io_loop.call_later = MagicMock()

        callback = MagicMock()
        key = 'test.key'
        default = 'default_value'
        self.toucan_monitor.register_toucan_key(key=key, callback=callback, default=default)

        new_value = 'new_value'

        self.toucan.get.return_value = new_value

        await self.toucan_monitor.monitor()

        callback.assert_called_once_with(key=key, value=new_value)
        self.io_loop.call_later.assert_called_once_with(60, self.toucan_monitor.monitor)

    @gen_test
    async def test_polling_with_exception(self):
        self.io_loop.call_later = MagicMock()

        callback = MagicMock()
        key = 'test.key'
        default = 'default_value'
        self.toucan_monitor.register_toucan_key(key=key, callback=callback, default=default)

        self.toucan.get.side_effect = Exception()

        await self.toucan_monitor.monitor()

        callback.assert_called_once_with(key=key, value=default)
        self.io_loop.call_later.assert_called_once_with(60, self.toucan_monitor.monitor)
