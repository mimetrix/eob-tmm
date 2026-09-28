"""Live exact-value checks while a separate collector container is replaced."""
import asyncio
import json
import time

import tao.test_types

from collector_client import page
from collector_suite import StreamingMethod
from method_suite import Method, method_test


class ContainerMethod(StreamingMethod):
    """Consumers use only the API socket; the host controls container replacement."""

    def __init__(self, output):
        super().__init__(output)
        self.control_sequence = 0
        self.result["container_controls"] = []

    async def page(self, cursor=None):
        """Read committed records through the socket."""
        return await asyncio.to_thread(page, "/collector-api/events.sock", cursor)

    async def start(self):
        """Keep the initial cursor, then attach the measured probe."""
        first = await self.page()
        self.result["stream_pages"].append(first)
        self.cursor = first["next_cursor"]
        self.initial_cursor = first["oldest_cursor"]
        assert not any(row["event"]["type"] == "record" for row in first["events"])
        await Method.start(self)

    async def control(self, action):
        """Ask the outer controller; no Docker socket is available to this client."""
        self.control_sequence += 1
        request = {"sequence": self.control_sequence, "action": action}
        temporary = self.output.parent / "control-request.tmp"
        temporary.write_text(json.dumps(request), encoding="utf-8")
        temporary.replace(self.output.parent / "control-request.json")
        response = self.output.parent / "control-response.json"
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if response.exists():
                value = json.loads(response.read_text(encoding="utf-8"))
                if value["sequence"] == self.control_sequence:
                    assert value["passed"], value
                    self.result["container_controls"].append(value)
                    return
            await asyncio.sleep(0.1)
        raise TimeoutError("collector container control did not complete")

    async def request(
        self, label, path, body, mime="application/json", fragmented=False
    ):
        """Send two of the original requests while the collector is stopped."""
        action = {"/empty": "stop", "/escaped": "kill"}.get(path)
        if action:
            await self.control(action)
        await super().request(label, path, body, mime=mime, fragmented=fragmented)
        if action:
            # The response has already passed its exact forwarding checks.
            # The next drain must obtain the value emitted during the outage.
            await self.control("resume")


async def container_test(log, config):
    """Keep all ten original traffic cases; replace only the collector."""
    return await method_test(log, config, test_class=ContainerMethod)


def publish_tests():
    """Expose the separate-container test to Tao."""
    return [
        tao.test_types.DockerBaseTest2("collector container restart", container_test)
    ]
