import socket
import json
import logging
import asyncio
from typing import Any

from .aes_utils import aes_encrypt, aes_decrypt
from .const import CONF_ID, CONF_IPADDRESS
from .exceptions import AidotOSError
from aidot.models.discover_model import DiscoverResponse, DiscoverRequest

_LOGGER = logging.getLogger(__name__)
_DISCOVER_FAST = 6  # 启动时快速发现
_DISCOVER_SLOW = 120  # 稳定后慢速维持


class BroadcastProtocol:
    _is_closed = False

    def __init__(self, callback, user_id) -> None:
        self.aes_key = bytearray(b"T54uednca587".ljust(32, b"\x00"))

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
        try:
            request = DiscoverRequest.from_params(userId=self.user_id)
            message = request.to_dict()
            _LOGGER.warning(f"send_broadcast {message}")
            send_data = aes_encrypt(json.dumps(message).encode(), self.aes_key)
            self.transport.sendto(send_data, ("255.255.255.255", 6666))
        except Exception as error:
            _LOGGER.error(f"{self.user_id}:Connection lost due to error: {error}")

    def datagram_received(self, data, addr) -> None:
        try:
            data_str = aes_decrypt(data, self.aes_key)
            data_json = json.loads(data_str)
            response = DiscoverResponse.from_json(data=data_json)
            _LOGGER.warning(f"datagram_received {data_json}")
            if response.payload and response.payload.devId and self._discover_cb:
                self._discover_cb(response.payload.devId, {CONF_IPADDRESS: addr[0]})
        except Exception as error:
            _LOGGER.error(f"datagram_received error: {error}")

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
    _timer_handle: asyncio.TimerHandle | None = None

    def __init__(self, login_info, callback):
        self.discovered_device = {}
        self._login_info = login_info
        self._callback = callback

    async def try_create_broadcast(self) -> None:
        if self._broadcast_protocol is not None:
            return
        try:
            protocol = BroadcastProtocol(
                self._discover_callback, self._login_info[CONF_ID]
            )
            (
                self._transport,
                _,
            ) = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: protocol,
                local_addr=("0.0.0.0", 0),
            )
            self._broadcast_protocol = protocol  # 成功后再赋值
        except OSError:
            raise AidotOSError

    def start_repeat_broadcast(self) -> None:
        self._is_close = False
        self._fast_discover_count = 5  # 前5次快速
        self._schedule_broadcast()

    def _schedule_broadcast(self) -> None:
        _LOGGER.warning("_schedule_broadcast")
        # 前几次快速发现，之后慢速
        if self._fast_discover_count > 0:
            interval = _DISCOVER_FAST
            self._fast_discover_count -= 1
        else:
            interval = _DISCOVER_SLOW

        loop = asyncio.get_running_loop()
        asyncio.create_task(self._do_broadcast())
        self._timer_handle = loop.call_later(interval, self._schedule_broadcast)

    async def _do_broadcast(self) -> None:
        """执行广播"""
        try:
            await self.try_create_broadcast()
            self._broadcast_protocol.send_broadcast()
        except Exception as e:
            _LOGGER.error(f"Broadcast failed: {e}")

    def _discover_callback(self, dev_id, event: dict[str, str]) -> None:
        self.discovered_device[dev_id] = event[CONF_IPADDRESS]
        if self._callback:
            self._callback(dev_id, event)

    def close(self) -> None:
        if self._timer_handle is not None:
            self._timer_handle.cancel()
            self._timer_handle = None
        if self._broadcast_protocol is not None:
            self._broadcast_protocol.close()
            self._broadcast_protocol = None
