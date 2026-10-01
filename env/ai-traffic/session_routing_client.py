"""Replay client that preserves HTTP failures before decoding JSON."""
import http.client
import json
import socket
from urllib.parse import urlencode


class ReplayUnavailable(OSError):
    """The journal reports temporary unavailability without cursor advancement."""


def page(path, cursor=None):
    class Connection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect(str(path))

    query = {'limit': 128, 'wait_ms': 0}
    if cursor is not None:
        query['after'] = cursor
    connection = Connection('localhost', timeout=15)
    try:
        connection.request('GET', '/events?' + urlencode(query))
        response = connection.getresponse()
        body = response.read()
        if response.status == 503:
            raise ReplayUnavailable(response.status, body[:512].decode(errors='replace'))
        if response.status != 200:
            raise ValueError(('replay_http_error', response.status, body[:512].decode(errors='replace')))
        try:
            return json.loads(body)
        except ValueError as error:
            raise ValueError(('replay_invalid_json', response.status, body[:512].hex())) from error
    finally:
        connection.close()
