"""Device client for AiDot TCP communication."""

import ctypes
import json
import logging
import socket
import struct
import asyncio
from enum import IntEnum
from typing import Any, Callable, Optional

from .utils import AsyncTimer, aes_decrypt_to_json, aes_encrypt
from .const import CONF_CCT, CONF_DIMMING, CONF_ON_OFF, CONF_RGBW, Identity
from .models.auth_model import UserInformation
from .models.device_client_model import (
    BaseRequest,
    DeviceActionRequest,
    DeviceAttr,
    DeviceProtocol,
    DeviceResponse,
    LoginRequest,
    PingRequest,
)
from .models.device_model import DeviceModel

_LOGGER = logging.getLogger(__name__)

# This model requires a shorter ping interval (15s) and uses
# getDevAttrReq as heartbeat instead of a standalone ping request.
_SPECIAL_PING_MODELS = {"lk.WIFI-RGBWLight-D0006"}


# =============================================================================
# Enums
# =============================================================================


class DeviceState(IntEnum):
    """Device connection state machine states."""

    IDLE = 0
    INITIALIZING = 1
    CONNECTING = 2
    CONNECTED = 3
    CONNECTION_FAILED = 4
    AUTHENTICATING = 5
    AUTHENTICATED = 6
    AUTHENTICATION_FAILED = 7
    DISCONNECTED = 8


# =============================================================================
# Data Classes
# =============================================================================


class DeviceStatusData:
    """Device status data (light state)."""

    online: bool = False
    on: bool = False
    rgdb: int = 0xFF000000
    rgbw: tuple[int, int, int, int] = (255, 0, 0, 0)
    cct: int = 2700
    dimming: int = 100

    def update(self, attr: DeviceAttr) -> None:
        """Update status from DeviceAttr model."""
        if attr is None:
            return

        if attr.OnOff is not None:
            self.on = attr.OnOff

        if attr.Dimming is not None:
            self.dimming = int(attr.Dimming * 255 / 100)

        if attr.RGBW is not None:
            rgbw_value = attr.RGBW
            if rgbw_value == 0:
                self.rgdb = 0xFF000000
            else:
                self.rgdb = rgbw_value

            rgbw = ctypes.c_uint32(self.rgdb).value
            r = (rgbw >> 24) & 0xFF
            g = (rgbw >> 16) & 0xFF
            b = (rgbw >> 8) & 0xFF
            w = rgbw & 0xFF
            self.rgbw = (r, g, b, w)

        if attr.CCT is not None:
            self.cct = attr.CCT


class DeviceInformation:
    """Device metadata inferred from DeviceModel and product definition."""

    enable_rgbw: bool = False
    enable_dimming: bool = True
    enable_cct: bool = False
    cct_min: int = 0
    cct_max: int = 0
    dev_id: str = ""
    mac: str = ""
    model_id: str = ""
    name: str = ""
    hw_version: str = ""
    password: str = ""
    simpleVersion: Optional[str] = None

    def __init__(self, device: DeviceModel) -> None:
        """Initialize device information from DeviceModel."""
        self.dev_id = device.id
        self.mac = device.mac
        self.model_id = device.modelId
        self.name = device.name
        self.hw_version = device.hardwareVersion
        self.password = device.password
        self.simpleVersion = device.simpleVersion

        if device.product:
            for service in device.product.serviceModules:
                if service.identity == Identity.RGBW:
                    self.enable_rgbw = True
                    self.enable_cct = True
                elif service.identity == Identity.CCT:
                    self.cct_min = int(service.properties[0].minValue)
                    self.cct_max = int(service.properties[0].maxValue)
                    self.enable_cct = True


# =============================================================================
# Device Client
# =============================================================================


class DeviceClient:
    """TCP client for AiDot device communication."""

    status: DeviceStatusData
    info: DeviceInformation
    _state: DeviceState = DeviceState.IDLE
    _ip_address: Optional[str] = None
    _is_close: bool = False
    on_status_update: Optional[Callable[[DeviceStatusData], None]] = None
    _receive_task: Optional[asyncio.Task] = None
    _reconnect_handle: Optional[asyncio.TimerHandle] = None
    _ping_timer: Optional[AsyncTimer] = None
    _reconnect_timer: Optional[AsyncTimer] = None
    writer: Optional[asyncio.StreamWriter] = None
    reader: Optional[asyncio.StreamReader] = None
    _device: Optional[DeviceModel] = None
    _user_info: Optional[UserInformation] = None
    _seq_num: int = 0
    _is_special_model: bool = False
    _TAG: str = "DeviceClient"
    syncProperties = [CONF_ON_OFF, CONF_DIMMING, CONF_RGBW, CONF_CCT]

    def __init__(self, device: DeviceModel, user_info: UserInformation) -> None:
        """Initialize device client with device model and user credentials."""
        self.ping_count = 0
        self.status = DeviceStatusData()
        self._device = device
        self._user_info = user_info
        self.info = DeviceInformation(self._device)

        if self._device.aesKey:
            self.aes_key = bytearray(16)
            key_bytes = self._device.aesKey[0].encode()
            self.aes_key[: len(key_bytes)] = key_bytes

        self._TAG = f"{self._device.id}"
        if self.info.model_id in _SPECIAL_PING_MODELS:
            self._is_special_model = True

    # =========================================================================
    # State Management
    # =========================================================================

    def update_state(self, state: DeviceState) -> None:
        """Update device state and log the transition."""
        self._state = state
        _LOGGER.info(f"{self._TAG}: State changed to {state.name}")

    def update_ip_address(self, ip: str) -> None:
        """Update device IP address and trigger connection."""
        self._ip_address = ip
        if self._state == DeviceState.IDLE:
            asyncio.create_task(self.async_login())

    # =========================================================================
    # Connection Management
    # =========================================================================

    async def async_login(self) -> None:
        """Connect and authenticate with the device."""
        if self._ip_address is None or self._state != DeviceState.IDLE:
            return

        try:
            self.update_state(DeviceState.CONNECTING)
            self.reader, self.writer = await asyncio.open_connection(
                self._ip_address,
                10000,  # AiDot device TCP port
            )

            sock: socket.socket = self.writer.get_extra_info("socket")
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.update_state(DeviceState.CONNECTED)

            self.update_state(DeviceState.AUTHENTICATING)
            login_request = LoginRequest(self._device, self._user_info.id)
            await self.write_request(login_request)

            login_data = await self.read_data()
            response = DeviceResponse.from_json(login_data)

            if response.ack.code != 200:
                self.update_state(DeviceState.AUTHENTICATION_FAILED)
                _LOGGER.error(f"{self._TAG}: Login failed, code: {response.ack.code}")
                await self.reset()
                return

            self.update_state(DeviceState.AUTHENTICATED)
            self.ascNumber = response.payload.ascNumber + 1
            self.status.online = True
            self._notify_status_update()

            self._receive_task = asyncio.create_task(
                self.receive_data(), name=f"aidot_receive_{self._device.id}"
            )

            self._start_ping()

            request = self.action_request(
                self.syncProperties, DeviceProtocol.METHOD_GET_DEV_ATTR_REQ
            )
            await self.write_request(request)
        except Exception as e:
            _LOGGER.error(f"{self._TAG}: Exception: {e}")
            self.update_state(DeviceState.CONNECTION_FAILED)
            asyncio.create_task(self.reset())

    async def reset(self) -> None:
        """Reset connection, cleanup resources, and schedule reconnect."""
        if self._ping_timer:
            self._ping_timer.cancel()

        if self._receive_task and not self._receive_task.done():
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass

        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception as e:
            _LOGGER.error(f"{self._TAG}: Close error: {e}")

        self.writer = None
        self.reader = None
        self.update_state(DeviceState.IDLE)
        self.status.online = False
        self.ping_count = 0
        self._notify_status_update()

        if not self._is_close and self._ip_address:
            _LOGGER.info(f"{self._TAG}: Scheduling reconnect in 45s")
            self._reconnect_timer = AsyncTimer(
                callback=self.async_login,
                interval=45,  # 45-second delay before reconnect attempt
            )
            self._reconnect_timer.start()

    async def close(self) -> None:
        """Permanently close connection (no reconnect) and cleanup."""
        self._is_close = True
        await self.reset()
        _LOGGER.info(f"{self._TAG}: Connection closed")

    # =========================================================================
    # Network I/O
    # =========================================================================

    async def write_request(self, request: BaseRequest) -> None:
        """Build encrypted TCP packet and send to device."""
        try:
            data_type = (
                DeviceProtocol.MSG_TYPE_HEARTBEAT
                if request.method == DeviceProtocol.METHOD_PING_REQ
                else DeviceProtocol.MSG_TYPE_DATA
            )

            magic = struct.pack(">H", 0x1EED)  # AiDot protocol magic number
            msgtype = struct.pack(">h", data_type)
            message = json.dumps(request.to_dict()).encode()

            if self.aes_key is not None:
                send_data = aes_encrypt(message, self.aes_key)
            else:
                send_data = message

            bodysize = struct.pack(">i", len(send_data))
            packet = magic + msgtype + bodysize + send_data

            self.writer.write(packet)
            await self.writer.drain()

        except (
            BrokenPipeError,
            ConnectionResetError,
            TimeoutError,
            ConnectionRefusedError,
        ) as e:
            _LOGGER.error(f"{self._TAG}: Write error: {e}")
            asyncio.create_task(self.reset())
        except Exception as e:
            _LOGGER.error(f"{self._TAG}: Write error: {e}")

    async def read_data(self) -> dict[str, Any]:
        """Read and decrypt one response frame from device."""
        header = await self.reader.readexactly(8)
        _, _, bodysize = struct.unpack(">HHI", header)
        body = await self.reader.readexactly(bodysize)
        return aes_decrypt_to_json(body, self.aes_key)

    async def receive_data(self) -> None:
        """Continuously receive and process data from device."""
        while self._state == DeviceState.AUTHENTICATED:
            try:
                json_data = await self.read_data()
                self.ping_count = 0
                _LOGGER.info(f"{self._TAG}: Received: {json_data}")

            except asyncio.CancelledError:
                _LOGGER.debug(f"{self._TAG}: Receive task cancelled")
                raise

            except (
                BrokenPipeError,
                ConnectionResetError,
                asyncio.IncompleteReadError,
                ConnectionRefusedError,
                TimeoutError,
            ) as e:
                _LOGGER.error(f"{self._TAG}: Read error: {e}")
                asyncio.create_task(self.reset())
                return

            except Exception as e:
                _LOGGER.error(f"{self._TAG}: Receive error: {e}")
                continue

            response = DeviceResponse.from_json(json_data)
            if response.service == DeviceProtocol.SERVICE_TEST:
                continue

            if response.payload.ascNumber:
                self.ascNumber = response.payload.ascNumber

            if response.payload.attr:
                self.status.update(response.payload.attr)
                self._notify_status_update()

    # =========================================================================
    # Heartbeat / Ping
    # =========================================================================

    def _start_ping(self) -> None:
        """Start heartbeat timer."""
        interval = 15 if self._is_special_model else 30

        async def _ping_callback() -> None:
            """Send ping or keep-alive attr request; disconnect after 3 missed pongs."""
            if self._state != DeviceState.AUTHENTICATED:
                return

            if self.ping_count >= 3:
                _LOGGER.error(f"{self._TAG}: Ping timeout, disconnecting")
                self.update_state(DeviceState.DISCONNECTED)
                await self.reset()
                return

            self.ping_count += 1

            if self._is_special_model:
                request = self.action_request(
                    self.syncProperties, DeviceProtocol.METHOD_GET_DEV_ATTR_REQ
                )
            else:
                request = PingRequest()
            await self.write_request(request)

        if self._ping_timer:
            self._ping_timer.cancel()

        self._ping_timer = AsyncTimer(
            callback=_ping_callback,
            interval=interval,
            repeat=True,
            name=f"aidot_ping_{self._device.id}",
        )
        self._ping_timer.start()

    # =========================================================================
    # Device Control
    # =========================================================================

    async def send_dev_attr(self, dev_attr: dict[str, Any]) -> None:
        """Send device attribute command. Auto-turns on the device if currently off."""
        if self._state != DeviceState.AUTHENTICATED:
            raise ConnectionError("Device offline")

        if not self.status.on and CONF_ON_OFF not in dev_attr:
            self.status.on = True
            dev_attr[CONF_ON_OFF] = 1

        request = self.action_request(dev_attr, DeviceProtocol.METHOD_SET_DEV_ATTR_REQ)
        await self.write_request(request)

    async def async_turn_on(self) -> None:
        """Turn device on."""
        await self.send_dev_attr({CONF_ON_OFF: 1})

    async def async_turn_off(self) -> None:
        """Turn device off."""
        await self.send_dev_attr({CONF_ON_OFF: 0})

    async def async_set_brightness(self, brightness: int) -> None:
        """Set device brightness (0-255)."""
        final_dimming = int(brightness * 100 / 255)
        await self.send_dev_attr({CONF_DIMMING: final_dimming})

    async def async_set_rgbw(self, rgbw: tuple[int, int, int, int]) -> None:
        """Set device RGBW color. Tuple order: (R, G, B, W), each 0-255."""
        final_rgbw = (rgbw[0] << 24) | (rgbw[1] << 16) | (rgbw[2] << 8) | rgbw[3]
        await self.send_dev_attr({CONF_RGBW: ctypes.c_int32(final_rgbw).value})

    async def async_set_cct(self, cct: int) -> None:
        """Set device color temperature in Kelvin."""
        await self.send_dev_attr({CONF_CCT: cct})

    # =========================================================================
    # Request Building
    # =========================================================================

    def action_request(self, attr: dict[str, Any], method: str) -> BaseRequest:
        """Build device action request."""
        self._seq_num += 1
        return DeviceActionRequest.from_params(
            method=method,
            user_id=self._user_info.id,
            device=self._device,
            ascNumber=self.ascNumber,
            attr=attr,
            seq="ha93" + str(self._seq_num).zfill(5),
        )

    # =========================================================================
    # Callbacks
    # =========================================================================

    def _notify_status_update(self) -> None:
        """Notify status update callback."""
        if self.on_status_update:
            self.on_status_update(self.status)
