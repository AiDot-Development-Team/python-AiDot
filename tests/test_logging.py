"""Routine traffic must not be logged at WARNING or above.

Home Assistant logs WARNING by default, so anything logged at that level on a
healthy connection ends up in every user's log.
"""

import asyncio
import json
import struct
import unittest
from typing import Any
from unittest.mock import AsyncMock, patch

from aidot.aes_utils import aes_encrypt
from aidot.client import AidotClient
from aidot.const import (
    CONF_AES_KEY,
    CONF_ID,
    CONF_MODEL_ID,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_PROPERTIES,
)
from aidot.device_client import DeviceClient
from aidot.discover import BroadcastProtocol, Discover

AES_KEY = "0123456789abcdef"


class FakeSocket:
    """Socket double accepting option changes."""

    def setsockopt(self, *args: Any) -> None:
        """Accept any socket option."""


class FakeWriter:
    """StreamWriter double recording written packets."""

    def __init__(self) -> None:
        self.packets: list[bytes] = []

    def write(self, data: bytes) -> None:
        """Record a packet."""
        self.packets.append(data)

    async def drain(self) -> None:
        """Nothing to flush."""

    def get_extra_info(self, name: str) -> Any:
        """Return a fake socket."""
        return FakeSocket()

    def close(self) -> None:
        """Nothing to close."""

    async def wait_closed(self) -> None:
        """Nothing to wait for."""


class FakeTransport:
    """DatagramTransport double recording sent datagrams."""

    def __init__(self) -> None:
        self.sent: list[tuple[bytes, Any]] = []

    def get_extra_info(self, name: str) -> Any:
        """Return a fake socket."""
        return FakeSocket()

    def sendto(self, data: bytes, addr: Any) -> None:
        """Record a datagram."""
        self.sent.append((data, addr))

    def close(self) -> None:
        """Nothing to close."""


def _device_packet(message: dict[str, Any]) -> bytes:
    """Encrypt a message the way a device sends it over TCP."""
    key = bytearray(16)
    key[: len(AES_KEY)] = AES_KEY.encode()
    body = aes_encrypt(json.dumps(message).encode(), key)
    return struct.pack(">HHI", 0x1EED, 1, len(body)) + body


class DeviceClientLoggingTest(unittest.IsolatedAsyncioTestCase):
    """A healthy device session stays below WARNING."""

    async def test_connect_ping_and_receive_do_not_log_warnings(self) -> None:
        """Connecting, pinging and receiving state updates is routine traffic."""
        reader = asyncio.StreamReader()
        reader.feed_data(
            _device_packet(
                {
                    "service": "device",
                    "method": "loginResp",
                    "seq": "1",
                    "srcAddr": "3.device-id",
                    "deviceId": "device-id",
                    "payload": {"ascNumber": 1},
                    "ack": {"code": 200, "desc": "login sucess"},
                }
            )
        )
        reader.feed_data(
            _device_packet(
                {
                    "service": "test",
                    "method": "pingresp",
                    "seq": "123456",
                    "srcAddr": "3.device-id",
                    "payload": {},
                    "ack": {"code": 200, "desc": "OK"},
                }
            )
        )
        reader.feed_data(
            _device_packet(
                {
                    "service": "device",
                    "method": "setDevAttrNotif",
                    "seq": "2",
                    "srcAddr": "3.device-id",
                    "payload": {"attr": {"OnOff": 1}, "ascNumber": 2},
                    "ack": {"code": 200, "desc": "OK"},
                }
            )
        )
        writer = FakeWriter()
        device = {
            CONF_ID: "device-id",
            CONF_NAME: "Test Light",
            CONF_MODEL_ID: "aidot.light.rgbw",
            CONF_AES_KEY: [AES_KEY],
            CONF_PASSWORD: "password",
            CONF_PROPERTIES: {},
        }
        device_client = DeviceClient(device, {CONF_ID: "user-id"}, None)

        with (
            patch("asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))),
            self.assertNoLogs("aidot", level="WARNING"),
        ):
            await device_client.connect("192.168.1.10")
            await device_client.send_ping_action()
            await device_client.async_turn_on()
            for _ in range(5):
                await asyncio.sleep(0)
            await device_client.close()

        self.assertTrue(device_client.status.on)
        self.assertGreaterEqual(len(writer.packets), 3)


class DiscoverLoggingTest(unittest.IsolatedAsyncioTestCase):
    """Periodic LAN discovery stays below WARNING."""

    async def test_broadcast_and_reply_do_not_log_warnings(self) -> None:
        """Sending a discovery broadcast and receiving a reply is routine."""
        discovered: list[tuple[str, dict[str, str]]] = []
        protocol = BroadcastProtocol(
            lambda dev_id, event: discovered.append((dev_id, event)), "user-id"
        )
        transport = FakeTransport()
        reply = aes_encrypt(
            json.dumps(
                {
                    "service": "device",
                    "method": "devDiscoveryResp",
                    "payload": {"devId": "device-id", "ip": "192.168.1.10"},
                }
            ).encode(),
            protocol.aes_key,
        )

        with self.assertNoLogs("aidot", level="WARNING"):
            protocol.connection_made(transport)
            protocol.send_broadcast()
            protocol.datagram_received(reply, ("192.168.1.10", 6666))

        self.assertEqual(len(transport.sent), 1)
        self.assertEqual(discovered, [("device-id", {"ipAddress": "192.168.1.10"})])

    async def test_discovery_loop_does_not_log_warnings(self) -> None:
        """Starting the client discovery loop is routine."""
        client = AidotClient(session=None)
        client.login_info = {CONF_ID: "user-id"}

        with (
            patch.object(Discover, "_do_broadcast", new=AsyncMock()),
            self.assertNoLogs("aidot", level="WARNING"),
        ):
            client.setup_discover()
            await asyncio.sleep(0)
            await client.async_close()


if __name__ == "__main__":
    unittest.main()
