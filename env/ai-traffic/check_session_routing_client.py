#!/usr/bin/env python3
"""Offline regression checks for status-first replay response handling."""
import io
import unittest
from unittest.mock import Mock, patch

from session_routing_client import ReplayUnavailable, page


class ReplayClientTests(unittest.TestCase):
    def socket_for(self, status, body):
        sock = Mock()
        sock.makefile.return_value = io.BytesIO(
            f'HTTP/1.1 {status} test\r\nContent-Length: {len(body)}\r\n\r\n'.encode() + body
        )
        return sock

    def test_valid_page_preserves_cursor(self):
        sock = self.socket_for(200, b'{"events":[],"next_cursor":"epoch:7"}')
        with patch('session_routing_client.socket.socket', return_value=sock):
            result = page('/fixture/events.sock', 'epoch:7')
        self.assertEqual(result, {'events': [], 'next_cursor': 'epoch:7'})
        request = b''.join(call.args[0] for call in sock.sendall.call_args_list)
        self.assertIn(b'after=epoch%3A7', request)
        sock.connect.assert_called_once_with('/fixture/events.sock')
        sock.close.assert_called_once()

    def test_only_503_is_retryable(self):
        for status in (400, 401, 404, 500, 503):
            with self.subTest(status=status):
                sock = self.socket_for(status, b'<html>unavailable</html>')
                with patch('session_routing_client.socket.socket', return_value=sock), \
                        patch('session_routing_client.json.loads') as loads:
                    error_type = ReplayUnavailable if status == 503 else ValueError
                    with self.assertRaises(error_type) as caught:
                        page('/fixture/events.sock', 'epoch:7')
                    loads.assert_not_called()
                self.assertIn(str(status), str(caught.exception))
                sock.close.assert_called_once()

    def test_bad_success_body_is_not_retryable(self):
        sock = self.socket_for(200, b'\xff<html>not JSON</html>')
        with patch('session_routing_client.socket.socket', return_value=sock):
            with self.assertRaises(ValueError) as caught:
                page('/fixture/events.sock')
        self.assertEqual(caught.exception.args[0][0:2], ('replay_invalid_json', 200))
        self.assertTrue(caught.exception.args[0][2].startswith('ff'))
        sock.close.assert_called_once()

    def test_error_diagnostic_is_bounded(self):
        sock = self.socket_for(400, b'x' * 1024)
        with patch('session_routing_client.socket.socket', return_value=sock):
            with self.assertRaises(ValueError) as caught:
                page('/fixture/events.sock')
        self.assertEqual(caught.exception.args[0][2], 'x' * 512)
        sock.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
