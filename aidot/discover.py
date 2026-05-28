import socket
import json
import logging
import asyncio
from typing import Callable, Optional

from .const import CONF_IPADDRESS
from .exceptions import AidotOSError
from aidot.models.discover_model import DiscoverResponse, DiscoverRequest
from aidot.models.auth_model import UserInformation
from .utils import AsyncTimer, aes_decrypt, aes_encrypt

_LOGGER = logging.getLogger(__name__)
_DISCOVER_FAST = 5  # 启动时快速发现
_DISCOVER_SLOW = 120  # 稳定后慢速维持
_DISCOVER_FAST_COUNT = 3


class BroadcastProtocol:
    _is_closed = False

    def __init__(self, callback) -> None:
        self.aes_key = bytearray(b"T54uednca587".ljust(32, b"\x00"))
        self._discover_cb = callback

    def connection_made(self, transport) -> None:
        self.transport = transport
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def send_broadcast(self, message: dict) -> None:
        if self._is_closed is True:
            _LOGGER.error(f"Connection is closed")
            return
        try:
            send_data = aes_encrypt(json.dumps(message).encode(), self.aes_key)
            self.transport.sendto(send_data, ("255.255.255.255", 6666))
        except Exception as error:
            _LOGGER.error(f"Connection lost due to error: {error}")

    def datagram_received(self, data, addr) -> None:
        try:
            data_str = aes_decrypt(data, self.aes_key)
            data_json = json.loads(data_str)
            response = DiscoverResponse.from_json(data=data_json)
            # _LOGGER.warning(f"datagram_received {data_json}")
            if response.payload and response.payload.devId and self._discover_cb:
                self._discover_cb(response.payload.devId, {CONF_IPADDRESS: addr[0]})
        except Exception as error:
            _LOGGER.error(f"datagram_received error: {error}")

    def error_received(self, exc) -> None:
        _LOGGER.error(f"Error occurred: {exc}")

    def close(self) -> None:
        try:
            self.transport.close()
        except Exception as error:
            _LOGGER.error(f"Connection lost due to error: {error}")

    def connection_lost(self, exc) -> None:
        self._is_closed = True
        if exc:
            _LOGGER.error(f"Connection lost due to error: {exc}")
        else:
            _LOGGER.info("Connection closed.")


class Discover:
    USER_INFO: Optional[UserInformation] = None
    DISCOVERED_DEVICE: dict[str, str] = {}
    BROADCAST_TIMER: Optional[AsyncTimer] = None
    _BROADCAST_PROTOCOL: BroadcastProtocol = None
    _CALL_BACK: Optional[Callable] = None

    _FAST_DISCOVER_COUNT: int = _DISCOVER_FAST_COUNT

    def __init__(self) -> None:
        raise TypeError("Discover is a static class and cannot be instantiated")

    @classmethod
    def set_user_info(cls, user_info: UserInformation) -> None:
        cls.USER_INFO = user_info
        cls._FAST_DISCOVER_COUNT = _DISCOVER_FAST_COUNT
        if user_info.id:
            # Initialize timer if not exists
            if cls.BROADCAST_TIMER is None:
                cls.BROADCAST_TIMER = AsyncTimer(
                    callback=cls._send_broadcast,
                    interval=_DISCOVER_FAST,
                    repeat=True,
                )
            asyncio.get_running_loop().call_soon(
                lambda: asyncio.create_task(cls._send_broadcast())
            )
            cls.BROADCAST_TIMER.set_interval(value=_DISCOVER_FAST, restart=False)
            cls.BROADCAST_TIMER.restart()

    @classmethod
    def set_call_back(cls, call_back) -> None:
        cls._CALL_BACK = call_back

    @classmethod
    async def _try_create_broadcast(cls) -> None:
        if cls._BROADCAST_PROTOCOL is not None:
            return
        try:
            protocol = BroadcastProtocol(cls._discover_callback)
            (
                cls._transport,
                _,
            ) = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: protocol,
                local_addr=("0.0.0.0", 0),
            )
            cls._BROADCAST_PROTOCOL = protocol  # 成功后再赋值
        except OSError:
            raise AidotOSError

    @classmethod
    async def _send_broadcast(cls) -> None:
        """开始重复广播"""
        try:
            await cls._try_create_broadcast()
            request = DiscoverRequest.from_params(userId=cls.USER_INFO.id)
            _LOGGER.warning(f"send_broadcast: {request.to_dict()}")
            cls._BROADCAST_PROTOCOL.send_broadcast(message=request.to_dict())
            cls._FAST_DISCOVER_COUNT -= 1
            if cls._FAST_DISCOVER_COUNT < 0:
                cls.BROADCAST_TIMER.set_interval(value=_DISCOVER_SLOW)
        except Exception as e:
            _LOGGER.error(f"Broadcast failed: {e}")

    @classmethod
    def _discover_callback(cls, dev_id, event: dict[str, str]) -> None:
        cls.DISCOVERED_DEVICE[dev_id] = event[CONF_IPADDRESS]
        if cls._CALL_BACK:
            cls._CALL_BACK(dev_id, event)
