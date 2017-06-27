from unittest.mock import patch, MagicMock, call

from tornado.concurrent import Future
from tornado.httpclient import HTTPError, HTTPResponse
from tornado.testing import gen_test, AsyncTestCase

from utils.exceptions import ToucanException, ToucanUnsetException, ToucanConnectionException
from utils.toucan import Toucan


class TestToucan(AsyncTestCase):

    def setUp(self):
        super(TestToucan, self).setUp()
        self.toucan = Toucan('test_prot://test_host:3000/')
        self.toucan._http_client = MagicMock()
        self.toucan._http_client.get.return_value = Future()
        self.toucan._http_client.put.return_value = Future()
        self.response = HTTPResponse(request=MagicMock(), code=200, buffer='')

    @gen_test
    async def test_get_404(self):
        self.response.code = 404
        self.toucan._http_client.get.side_effect = (HTTPError(code=404, response=self.response))
        with self.assertRaises(ToucanUnsetException):
            await self.toucan.get("test.key")

    @patch('utils.toucan.Toucan.min_retry_time', 0)
    @gen_test
    async def test_get_502(self):
        self.response.code = 502
        self.response._body = b'{"message": "test_error"}'
        self.toucan._http_client.get.side_effect = (HTTPError(code=502, response=self.response))
        with self.assertRaises(ToucanConnectionException):
            await self.toucan.get("test.key")

    @patch('utils.toucan.Toucan.min_retry_time', 0)
    @gen_test
    async def test_get_502_invalid_json(self):
        self.response.code = 502
        self.response._body = b'test_error'
        self.toucan._http_client.get.side_effect = (HTTPError(code=502, response=self.response))
        with self.assertRaises(ToucanConnectionException):
            await self.toucan.get("test.key")

    @gen_test
    async def test_get_500(self):
        self.response.code = 500
        self.toucan._http_client.get.side_effect = (HTTPError(code=500, response=self.response))
        with self.assertRaises(ToucanException):
            await self.toucan.get("test.key")

    @patch('utils.toucan.ujson.loads')
    @gen_test
    async def test_get_toucan_error(self, mock_json):
        json_data = {
            'status': 'ERROR',
            'message': 'test_message'
        }
        self.response.code = 200
        self.response._body = b''
        self.toucan._http_client.get.return_value.set_result(self.response)
        mock_json.return_value = json_data

        with self.assertRaises(ToucanException):
            await self.toucan.get("test.key")

    @patch('utils.toucan.Toucan.min_retry_time', 1)
    @patch('utils.toucan.Toucan.max_retry_time', 4)
    @patch('utils.toucan.Toucan.max_retry_count', 5)
    @patch('utils.toucan.time.sleep')
    @gen_test
    async def test_try_if_fail_decorator_time_exceeded(self, mock_sleep):
        self.response.code = 502
        self.response._body = b'{"message": "test_error"}'
        self.toucan._http_client.get.side_effect = (HTTPError(code=502, response=self.response))

        with self.assertRaises(ToucanConnectionException):
            await self.toucan.get("test.key")
        mock_sleep.assert_has_calls([call(1), call(2), call(4), call(4), call(4)], True)

    @patch('utils.toucan.ujson.loads')
    @gen_test
    async def test_get_data(self, mock_json):
        self.response.code = 200
        self.response._body = b''
        self.toucan._http_client.get.return_value.set_result(self.response)
        expected = 'test_value'
        json_data = {
            'status': 'OK',
            'key': '/test/key',
            'value': expected
        }
        mock_json.return_value = json_data

        result = await self.toucan.get("test.key")

        self.assertEqual(result, expected)

    @patch('utils.toucan.ujson.loads')
    @gen_test
    async def test_get_empty_multiple_data(self, mock_json):
        expected = {'test': {}}
        json_data = [
            {
                'status': 'ERROR',
                'key': '/aucote/test/key_invalid'
            },
            {
                'status': 'OK',
                'key': '/aucote/test',
                'value': 'test_value'
            }
        ]
        self.response.code = 200
        self.response._body = b''
        self.toucan._http_client.get.return_value.set_result(self.response)
        mock_json.return_value = json_data

        result = await self.toucan.get("test.*")

        self.assertEqual(result, expected)

    @patch('utils.toucan.ujson.loads')
    @gen_test
    async def test_get_multiple_data(self, mock_json):
        expected = {'test.key': 'test_value'}
        json_data = [
            {
                'status': 'ERROR',
                'key': '/aucote/test/key_invalid'
            },
            {
                'status': 'OK',
                'key': '/aucote/test/key',
                'value': 'test_value'
            }
        ]
        self.response.code = 200
        self.response._body = b''
        self.toucan._http_client.get.return_value.set_result(self.response)
        mock_json.return_value = json_data

        result = await self.toucan.get("test.*")

        self.assertEqual(result, expected)

    @patch('utils.toucan.ujson.loads')
    @gen_test
    async def test_get_multiple_data_without_multivalue_key(self, mock_json):
        expected = {'test.key': 'test_value', 'test.key2': 'test_value_2'}
        json_data = [
            {
                'status': 'ERROR',
                'key': '/aucote/test/key_invalid'
            },
            {
                'status': 'OK',
                'key': '/aucote/test/key',
                'value': 'test_value'
            },
            {
                'status': 'OK',
                'key': '/aucote/test/key2',
                'value': 'test_value_2'
            },
            {
                'status': 'OK',
                'key': '/aucote/test',
                'value': 'test_value_asterisk'
            }
        ]
        self.response.code = 200
        self.response._body = b''
        self.toucan._http_client.get.return_value.set_result(self.response)
        mock_json.return_value = json_data

        result = await self.toucan.get("test.*")

        self.assertEqual(result, expected)

    @patch('utils.toucan.ujson.loads')
    @gen_test
    async def test_get_non_dict_nor_list(self, mock_json):
        json_data = 5
        self.response.code = 200
        self.response._body = b''
        self.toucan._http_client.get.return_value.set_result(self.response)
        mock_json.return_value = json_data

        with self.assertRaises(ToucanException):
            await self.toucan.get('test.key')

    @patch('utils.toucan.Toucan.min_retry_time', 0)
    @gen_test
    async def test_put_with_exception(self):
        self.toucan._http_client.put.side_effect = (HTTPError(code=500, response=self.response))

        with self.assertRaises(Exception):
            await self.toucan.put("test.key", "test_value")
        self.assertEqual(self.toucan._http_client.put.call_count, 1)

    @patch('utils.toucan.Toucan.min_retry_time', 0)
    @gen_test
    async def test_put_with_exception_404(self):
        self.response.code = 404
        self.toucan._http_client.put.side_effect = (HTTPError(code=404, response=self.response))

        with self.assertRaises(Exception):
            await self.toucan.put("test.key", "test_value")
        self.assertEqual(self.toucan._http_client.put.call_count, 1)

    @patch('utils.toucan.Toucan.min_retry_time', 0)
    @patch('utils.toucan.Toucan.max_retry_count', 1)
    @patch('utils.toucan.ujson.loads')
    @gen_test
    async def test_put_with_exception_502(self, mock_json):
        self.response.code = 502
        self.response._body = b''
        self.toucan._http_client.put.side_effect = (HTTPError(code=502, response=self.response))

        mock_json.return_value = {
            'message': 'test'
        }

        with self.assertRaises(ToucanConnectionException):
            await self.toucan.put("test.key", "test_value")
        self.assertEqual(self.toucan._http_client.put.call_count, 1)

    @gen_test
    async def test_push_config_exists_without_overwrite(self):
        config = {
            'test': {
                'key': {
                    'test_key': 'test_value'
                }
            }
        }
        self.toucan.put = MagicMock()
        self.toucan.get = MagicMock(return_value=Future())
        self.toucan.get.return_value.set_result({'test.key.test_key': 'test_value'})

        await self.toucan.push_config(config, overwrite=False)
        self.assertFalse(self.toucan.put.called)

    @gen_test
    async def test_push_config_non_exists_without_overwrite(self):
        config = {
            'test': {
                'key': {
                    'test_key': 'test_value'
                }
            }
        }
        self.toucan.put = MagicMock(return_value=Future())
        self.toucan.put.return_value.set_result(MagicMock())
        self.toucan.get = MagicMock(return_value=Future())
        self.toucan.get.return_value.set_result({})

        await self.toucan.push_config(config, overwrite=False)
        self.toucan.put.assert_called_once_with("*", {'test.key.test_key': 'test_value'})

    @gen_test
    async def test_push_config_non_exists_exception_without_overwrite(self):
        config = {
            'test': {
                'key': {
                    'test_key': 'test_value'
                }
            }
        }
        self.toucan.put = MagicMock(return_value=Future())
        self.toucan.put.return_value.set_result(MagicMock())
        self.toucan.get = MagicMock(side_effect=ToucanUnsetException)

        await self.toucan.push_config(config, overwrite=False)
        self.toucan.put.assert_called_once_with("*", {'test.key.test_key': 'test_value'})

    @gen_test
    async def test_push_config_with_overwrite(self):
        config = {
            'test': {
                'key': {
                    'test_key': 'test_value'
                }
            }
        }

        put_json = {
            'test.key.test_key': 'test_value'
        }
        self.toucan.put = MagicMock(return_value=Future())
        self.toucan.put.return_value.set_result(MagicMock())

        await self.toucan.push_config(config, overwrite=True)
        self.toucan.put.assert_called_once_with("*", put_json)

    def test_prepare_config(self):
        config = {
            'test': {
                'key': {
                    'test_key': 'test_value'
                },
                'other_key': 'test'
            }
        }
        self.toucan.put = MagicMock()

        result = self.toucan.prepare_config(config)
        expected = {
            'test.key.test_key': 'test_value',
            'test.other_key': 'test'
        }
        self.assertEqual(result, expected)

    @patch('utils.toucan.ujson.loads')
    @gen_test
    async def test_put_special_key_data(self, mock_json):
        expected = {'test.key': 'test_value'}
        put_data = {
            'test.key': 'test_value'
        }

        json_data = [{
            'status': 'OK',
            'key': '/aucote/test/key',
            'value': 'test_value'
        }]

        expected_put_data = [{
            'key': '/aucote/test/key',
            'value': 'test_value'
        }]

        self.toucan._http_client.put.return_value = Future()
        self.toucan._http_client.put.return_value.set_result(MagicMock())
        mock_json.return_value = json_data
        result = await self.toucan.put("*", put_data)

        self.assertEqual(result, expected)
        self.toucan._http_client.put.assert_called_once_with(url='test_prot://test_host:3000/config/*',
                                                             json=expected_put_data)

    @gen_test
    async def test_put_special_keys_with_exception(self):
        self.toucan.is_special = MagicMock(return_value=True)
        with self.assertRaises(ToucanException):
            await self.toucan.put("*", 'data')

    def test_special_asterisk(self):
        self.assertTrue(self.toucan.is_special('test.endpoint.*'))

    def test_non_special(self):
        self.assertFalse(self.toucan.is_special('test.other.endpoint'))
