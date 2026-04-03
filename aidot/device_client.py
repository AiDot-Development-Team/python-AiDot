"""The aidot integration."""

import ctypes
import socket
import struct
import time
import json
import asyncio
import logging
from datetime import datetime
from typing import Any

from .exceptions import AidotNotLogin
from .aes_utils import aes_encrypt, aes_decrypt
from .const import (
    CONF_AES_KEY,
    CONF_ASCNUMBER,
    CONF_ATTR,
    CONF_CCT,
    CONF_HARDWARE_VERSION,
    CONF_ID,
    CONF_IDENTITY,
    CONF_MAC,
    CONF_MAXVALUE,
    CONF_MINVALUE,
    CONF_MODEL_ID,
    CONF_NAME,
    CONF_ON_OFF,
    CONF_DIMMING,
    CONF_PASSWORD,
    CONF_PAYLOAD,
    CONF_PRODUCT,
    CONF_PROPERTIES,
    CONF_RGBW,
    CONF_SERVICE_MODULES,
    CONF_ACK,
    CONF_CODE,
    Identity,
)

_LOGGER = logging.getLogger(__name__)


class DeviceStatusData:
    online: bool = False
    on: bool = False
    rgdb: int = None
    rgbw: tuple[int, int, int, int] = None
    cct: int = None
    dimming: int = None

    def update(self, attr: dict[str, Any]) -> None:
        if attr is None:
            return
        if attr.get(CONF_ON_OFF) is not None:
            self.on = attr.get(CONF_ON_OFF)
        if attr.get(CONF_DIMMING) is not None:
            self.dimming = int(attr.get(CONF_DIMMING) * 255 / 100)
        if attr.get(CONF_RGBW) is not None:
            self.rgdb = attr.get(CONF_RGBW)
            rgbw = ctypes.c_uint32(self.rgdb).value
            r = (rgbw >> 24) & 0xFF
            g = (rgbw >> 16) & 0xFF
            b = (rgbw >> 8) & 0xFF
            w = rgbw & 0xFF
            self.rgbw = (r, g, b, w)
        if attr.get(CONF_CCT) is not None:
            self.cct = attr.get(CONF_CCT)


class DeviceInformation:
    enable_rgbw: bool = False
    enable_dimming: bool = True
    enable_cct: bool = False
    cct_min: int
    cct_max: int
    dev_id: str
    mac: str
    model_id: str
    name: str
    hw_version: str

    def __init__(self, device: dict[str, Any]) -> None:
        self.dev_id = device.get(CONF_ID)
        self.mac = device.get(CONF_MAC) if device.get(CONF_MAC) is not None else ""
        self.model_id = device.get(CONF_MODEL_ID)
        self.name = device.get(CONF_NAME)
        self.hw_version = device.get(CONF_HARDWARE_VERSION)
        if CONF_PRODUCT in device and CONF_SERVICE_MODULES in device[CONF_PRODUCT]:
            for service in device[CONF_PRODUCT][CONF_SERVICE_MODULES]:
                if service[CONF_IDENTITY] == Identity.RGBW:
                    self.enable_rgbw = True
                    self.enable_cct = True
                elif service[CONF_IDENTITY] == Identity.CCT:
                    self.cct_min = int(service[CONF_PROPERTIES][0][CONF_MINVALUE])
                    self.cct_max = int(service[CONF_PROPERTIES][0][CONF_MAXVALUE])
                    self.enable_cct = True


class DeviceClient(object):
    status: DeviceStatusData
    info: DeviceInformation
    _login_uuid = 0
    _connect_and_login: bool = False
    _connecting: bool = False
    _simpleVersion: str = ""
    _ip_address: str = None
    device_id: str
    _is_close: bool = False
    on_status_update: Any = None
    _receive_task: Any = None
    _login_task: Any = None
    _reconnect_handle: Any = None
    _ping_timer: Any = None
    writer: Any = None
    reader: Any = None
    _TAG: str = "DeviceClient"
    @property
    def connect_and_login(self) -> bool:
        return self._connect_and_login

    @property
    def connecting(self) -> bool:
        return self._connecting

    def __init__(self, device: dict[str, Any], user_info: dict[str, Any]) -> None:
        self.writer = None
        self.reader = None
        self.ping_count = 0
        self.status = DeviceStatusData()
        self.info = DeviceInformation(device)
        self.user_id = user_info.get(CONF_ID)

        if CONF_AES_KEY in device:
            key_string = device[CONF_AES_KEY][0]
            if key_string is not None:
                self.aes_key = bytearray(16)
                key_bytes = key_string.encode()
                self.aes_key[: len(key_bytes)] = key_bytes

        self.password = device.get(CONF_PASSWORD)
        self.device_id = device.get(CONF_ID)
        self._simpleVersion = device.get("simpleVersion")
        self._TAG = f"{self.device_id}";
        _LOGGER.warning(f"{self._TAG}:{device}")

    async def connect(self, ip_address) -> None:
        _LOGGER.warning(f"{self._TAG}:connect device: {ip_address}")
        self.reader = self.writer = None
        self._connecting = True
        try:
            self.reader, self.writer = await asyncio.open_connection(ip_address, 10000)
            sock: socket.socket = self.writer.get_extra_info("socket")
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.seq_num = 1
            await self.login()
            self._connect_and_login = True
        except Exception as e:
            self._connect_and_login = False
        finally:
            self._connecting = False

    def update_ip_address(self, ip: str) -> None:
        if ip is None:
            return
        self._ip_address = ip
        if self._connecting is not True and self._connect_and_login is not True:
            self._login_task = asyncio.create_task(self.async_login())

        
    async def async_login(self) -> None:
        if self._ip_address is None:
            return
        if self._connecting is not True and self._connect_and_login is not True:
            await self.connect(self._ip_address)

    def get_send_packet(self, message, msgtype):
        magic = struct.pack(">H", 0x1EED)
        _msgtype = struct.pack(">h", msgtype)

        if self.aes_key is not None:
            send_data = aes_encrypt(message, self.aes_key)
        else:
            send_data = message

        bodysize = struct.pack(">i", len(send_data))
        packet = magic + _msgtype + bodysize + send_data

        return packet
    
    def _notify_status_update(self) -> None:
        if self.on_status_update:
            self.on_status_update(self.status)
        

    async def login(self) -> None:
        login_seq = str(int(time.time() * 1000) + self._login_uuid)[-9:]
        self._login_uuid += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        message = {
            "service": "device",
            "method": "loginReq",
            "seq": login_seq,
            "srcAddr": self.user_id,
            "deviceId": self.device_id,
            "payload": {
                "userId": self.user_id,
                "password": self.password,
                "timestamp": timestamp,
                "ascNumber": 1,
            },
        }
        try:
            self.writer.write(self.get_send_packet(json.dumps(message).encode(), 1))
            await self.writer.drain()
            header = await self.reader.readexactly(8)
            magic, msgtype, bodysize = struct.unpack(">HHI", header)
            body = await self.reader.readexactly(bodysize)
            decrypted_data = aes_decrypt(body, self.aes_key) if self.aes_key else body
            json_data = json.loads(decrypted_data)
            code = json_data[CONF_ACK][CONF_CODE]
        
            if code != 200:
                # 登录失败
                _LOGGER.error(f"{self._TAG}:login error, code: {code}")
                await self.reset()
                return

            self.ascNumber = json_data[CONF_PAYLOAD][CONF_ASCNUMBER] + 1
            self.status.online = True
            self._receive_task = asyncio.create_task(
                self.receive_data(),
                name=f"aidot_receive_{self.device_id}"
            )
            if self._ping_timer:
                self._ping_timer.cancel()
            if self._reconnect_handle:
                self._reconnect_handle.cancel()
                self._reconnect_handle = None
            self._schedule_ping()
            _LOGGER.warning(f"{self._TAG}:connect success: {self._ip_address}")
            await self.send_action({}, "getDevAttrReq")
        except (BrokenPipeError, ConnectionResetError, Exception) as e:
            _LOGGER.error(f"{self.device_id} login read status error {e}")

    # TCP容易拼包，需要谨慎处理
    async def receive_data(self) -> None:
        while True:
            try:
                header = await self.reader.readexactly(8)
                magic, msgtype, bodysize = struct.unpack(">HHI", header)
                self.ping_count = 0 #有读到数据就把ping清零
                body = await self.reader.readexactly(bodysize)
                decrypted_data = aes_decrypt(body, self.aes_key)
                json_data = json.loads(decrypted_data)
                _LOGGER.warning(f"{self._TAG}:reveive_data : {json_data}")
            except asyncio.CancelledError:
                _LOGGER.debug(f"{self._TAG}:Receive task cancelled")
                raise
            except (BrokenPipeError, ConnectionResetError, asyncio.IncompleteReadError) as e:
                _LOGGER.error(f"{self._TAG}:read status error {e}")
                # await self.reset()
                syncio.get_running_loop().call_soon(
                    lambda: asyncio.create_task(self.reset())
                )
                return
            except Exception as e:
                _LOGGER.error(f"{self._TAG}:recv error: {e}")
                self.ping_count = 0
                continue

            if "service" in json_data:
                if "test" == json_data["service"]:
                    self.ping_count = 0
                    continue

            payload = json_data.get(CONF_PAYLOAD)
            if payload is not None:
                self.ascNumber = payload.get(CONF_ASCNUMBER)
                self.status.update(payload.get(CONF_ATTR))
                self._notify_status_update()
    
    def _schedule_ping(self):
        loop = asyncio.get_running_loop()
        loop.create_task(self.send_ping_action())
        self._ping_timer = loop.call_later(30, self._schedule_ping)

    async def send_dev_attr(self, dev_attr) -> None:
        if not self._connect_and_login:
            raise ConnectionError('Device offline')
        await self.send_action(dev_attr, "setDevAttrReq")

    async def async_turn_off(self) -> None:
        await self.send_dev_attr({CONF_ON_OFF: 0})

    async def async_turn_on(self) -> None:
        await self.send_dev_attr({CONF_ON_OFF: 1})

    async def async_set_brightness(self, brightness: int) -> None:
        final_dimming = int(brightness * 100 / 255)
        await self.send_dev_attr({CONF_DIMMING: final_dimming})

    async def async_set_rgbw(self, rgbw: tuple[int, int, int, int]) -> None:
        final_rgbw = (rgbw[0] << 24) | (rgbw[1] << 16) | (rgbw[2] << 8) | rgbw[3]
        await self.send_dev_attr({CONF_RGBW: ctypes.c_int32(final_rgbw).value})

    async def async_set_cct(self, cct: int) -> None:
        await self.send_dev_attr({CONF_CCT: cct})

    async def send_action(self, attr, method) -> None:
        current_timestamp_milliseconds = int(time.time() * 1000)
        self.seq_num += 1
        seq = "ha93" + str(self.seq_num).zfill(5)
        if not self.status.on and not CONF_ON_OFF in attr:
            self.status.on = True
            attr[CONF_ON_OFF] = 1

        if self._simpleVersion is not None:
            action = {
                "method": method,
                "service": "device",
                "clientId": "ha-" + self.user_id,
                "srcAddr": "0." + self.user_id,
                "seq": "" + seq,
                "payload": {
                    "devId": self.device_id,
                    "parentId": self.device_id,
                    "userId": self.user_id,
                    "password": self.password,
                    "attr": attr,
                    "channel": "tcp",
                    "ascNumber": self.ascNumber,
                },
                "tst": current_timestamp_milliseconds,
                "deviceId": self.device_id,
            }
        else:
            action = {
                "method": method,
                "service": "device",
                "seq": "" + seq,
                "srcAddr": "0." + self.user_id,
                "payload": {
                    "attr": attr,
                    "ascNumber": self.ascNumber,
                },
                "tst": current_timestamp_milliseconds,
                "deviceId": self.device_id,
            }

        try:
            self.writer.write(self.get_send_packet(json.dumps(action).encode(), 1))
            await self.writer.drain()
        except (BrokenPipeError, ConnectionResetError) as e:
            _LOGGER.error(f"{self._TAG}:send action error {e}")
            await self.reset()
        except Exception as e:
            _LOGGER.error(f"{self._TAG}:send action error {e}")

    async def send_ping_action(self) -> int:
        if self._is_close:
            return -1
        ping = {
            "service": "test",
            "method": "pingreq",
            "seq": "123456",
            "srcAddr": "x.xxxxxxx",
            CONF_PAYLOAD: {},
        }
        # _LOGGER.info(f"{self.device_id} send_ping_action {ping}")
        try:
            if self.ping_count >= 3:
                _LOGGER.error(
                    f"{self._TAG}:Device unresponsive within 90 seconds, disconnecting."
                )
                await self.reset()
                return -1
            if self._connect_and_login is False:
                return -1
            self.writer.write(self.get_send_packet(json.dumps(ping).encode(), 2))
            await self.writer.drain()
            self.ping_count += 1
            return 1
        except Exception as e:
            _LOGGER.error(f"{self.device_id} ping error {e}")
            await self.reset()
            return -1

    async def reset(self) -> None:
        if self._ping_timer:
            self._ping_timer.cancel()
        if self._reconnect_handle:
            self._reconnect_handle.cancel()
            self._reconnect_handle = None

        if self._receive_task and not self._receive_task.done():
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError as e:
                _LOGGER.error(f"{self.device_id} writer close error {e}")
                pass
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception as e:
            _LOGGER.error(f"{self.device_id} writer/reader close error {e}")
        self.writer = self.reader = None;

        self._connect_and_login = False
        self.status.online = False
        self.ping_count = 0
        self._notify_status_update()
        # 自动重连（如果没有主动关闭）
        if not self._is_close and self._ip_address:
            self._schedule_reconnect()

    async def close(self) -> None:
        self._is_close = True
        await self.reset()
        _LOGGER.info(f"{self.device_id} connect close by user")

    def _schedule_reconnect(self) -> None:
        """延迟重连"""
        _LOGGER.info(f"{self.device_id} _schedule_reconnect")
        loop = asyncio.get_running_loop()
        # self._reconnect_handle = loop.call_later(
        #     10,  # 10秒后重连
        #     lambda: asyncio.create_task(self.async_login())
        # )
        self._reconnect_handle = loop.call_later(15, self._schedule_reconnect)
        self._login_task = asyncio.create_task(self.async_login())
