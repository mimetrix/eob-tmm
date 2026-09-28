"""Read one bounded replay page through the collector's local Unix socket."""
import http.client
import json
import socket
from urllib.parse import urlencode


def page(path, cursor=None, limit=128, wait_ms=0):
    class Connection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect(str(path))

    query = {"limit": limit, "wait_ms": wait_ms}
    if cursor is not None:
        query["after"] = cursor
    connection = Connection("localhost", timeout=15)
    try:
        connection.request("GET", "/events?" + urlencode(query))
        response = connection.getresponse()
        data = json.loads(response.read())
        if response.status != 200:
            raise ValueError((response.status, data))
        return data
    finally:
        connection.close()
