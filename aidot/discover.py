import socket
import json
import time
import logging
import asyncio
from typing import Any

from .aes_utils import aes_encrypt, aes_decrypt
from .const import CONF_ID, CONF_IPADDRESS
from .exceptions import AidotOSError

_LOGGER = logging.getLogger(__name__)
_DISCOVER_TIME = 5


class BroadcastProtocol:
    _is_closed = False

    def __init__(self, callback, user_id) -> None:
        self.aes_key = bytearray(32)
        key_string = "T54uednca587"
        key_bytes = key_string.encode()
        self.aes_key[: len(key_bytes)] = key_bytes

        self._discover_cb = callback
        self.user_id = user_id

    def connection_made(self, transport) -> None:
        self.transport = transport
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def send_broadcast(self) -> None:
        if self._is_closed is True:
            _LOGGER.error(f"{self.user_id}:Connection is closed")
            return
        current_timestamp_milliseconds = int(time.time() * 1000)
        seq = str(current_timestamp_milliseconds + 1)[-9:]
        message = {
            "protocolVer": "2.0.0",
            "service": "device",
            "method": "devDiscoveryReq",
            "seq": seq,
            "srcAddr": f"0.{self.user_id}]",
            "tst": current_timestamp_milliseconds,
            "payload": {
                "extends": {},
                "localCtrFlag": 1,
                "timestamp": str(current_timestamp_milliseconds),
            },
        }
        send_data = aes_encrypt(json.dumps(message).encode(), self.aes_key)
        try:
            self.transport.sendto(send_data, ("255.255.255.255", 6666))
        except Exception as error:
            _LOGGER.error(f"{self.user_id}:Connection lost due to error: {error}")

    def datagram_received(self, data, addr) -> None:
        data_str = aes_decrypt(data, self.aes_key)
        data_json = json.loads(data_str)
        if "payload" in data_json:
            if "mac" in data_json["payload"]:
                devId = data_json["payload"]["devId"]
                if self._discover_cb:
                    self._discover_cb(devId, {CONF_IPADDRESS: addr[0]})

    def error_received(self, exc) -> None:
        _LOGGER.error(f"{self.user_id}:Error occurred: {exc}")

    def close(self) -> None:
        try:
            self.transport.close()
        except Exception as error:
            _LOGGER.error(f"Connection lost due to error: {error}")

    def connection_lost(self, exc) -> None:
        self._is_closed = True
        if exc:
            _LOGGER.error(f"{self.user_id}:Connection lost due to error: {exc}")
        else:
            _LOGGER.info("{self.user_id}:Connection closed.")


class Discover:
    _login_info: dict[str, Any] = None
    _broadcast_protocol: BroadcastProtocol = None
    discovered_device: dict[str, str]
    _is_close: bool = False

    def __init__(self, login_info, callback):
        self.discovered_device = {}
        self._login_info = login_info
        self._callback = callback

    async def try_create_broadcast(self) -> None:
        if self._broadcast_protocol is None:
            self._broadcast_protocol = BroadcastProtocol(
                self._discover_callback, self._login_info[CONF_ID]
            )
            try:
                (
                    transport,
                    protocol,
                ) = await asyncio.get_event_loop().create_datagram_endpoint(
                    lambda: self._broadcast_protocol,
                    local_addr=("0.0.0.0", 0),
                )
            except OSError:
                raise AidotOSError

    async def send_broadcast(self) -> None:
        await self.try_create_broadcast()
        self._broadcast_protocol.send_broadcast()

    async def repeat_broadcast(self) -> None:
        self._is_close = False
        while True:
            await self.send_broadcast()
            for i in range(_DISCOVER_TIME):
                await asyncio.sleep(1)  # 每秒检查一次是否需要取消任务
                if self._is_close is True:
                    return

    async def fetch_devices_info(self) -> dict[str, str]:
        self.try_create_broadcast()
        self._broadcast_protocol.send_broadcast()
        await asyncio.sleep(2)
        return self.discovered_device

    def _discover_callback(self, dev_id, event: dict[str, str]) -> None:
        self.discovered_device[dev_id] = event[CONF_IPADDRESS]
        if self._callback:
            self._callback(dev_id, event)

    def close(self) -> None:
        self._is_close = True
        if self._broadcast_protocol is not None:
            self._broadcast_protocol.close()
            self._broadcast_protocol = None
