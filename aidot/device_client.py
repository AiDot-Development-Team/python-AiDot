import socket
import struct
import time
from datetime import datetime
import json
import asyncio
import logging
from typing import Any
from .const import *
from .exceptions import AidotNotLogin

from .aes_utils import aes_encrypt, aes_decrypt

_LOGGER = logging.getLogger(__name__)


class DeviceStatusData:
    online: bool = False
    on: bool = False
    rgdb: int = None
    cct: int = None
    dimming: int = None

    def update(self, attr: dict[str, Any]) -> None:
        if attr is None:
            return
        if attr.get(CONF_ON_OFF) is not None:
            self.on = attr.get(CONF_ON_OFF)
        if attr.get(CONF_DIMMING) is not None:
            self.dimming = attr.get(CONF_DIMMING)
        if attr.get(CONF_RGBW) is not None:
            self.rgdb = attr.get(CONF_RGBW)
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

    def __init__(self, device: dict[str:Any]):
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
    _connecting = False
    _simpleVersion = ""
    _color_mode = ""
    _ip_address: str
    device_id: str

    @property
    def connect_and_login(self) -> bool:
        return self._connect_and_login

    @property
    def connecting(self) -> bool:
        return self._connecting

    @property
    def color_mode(self) -> str:
        return self._color_mode

    def __init__(self, device: dict, user_info: dict) -> None:
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

    async def connect(self, ipAddress):
        self.reader = self.writer = None
        self._connecting = True
        try:
            self.reader, self.writer = await asyncio.open_connection(ipAddress, 10000)
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
        self._ip_address = ip

    async def async_login(self) -> None:
        if self._ip_address is None:
            return
        if self._connecting is not True and self._connect_and_login is not True:
            await self.connect(self._ip_address)

    def getSendPacket(self, message, msgtype):
        magic = struct.pack(">H", 0x1EED)
        _msgtype = struct.pack(">h", msgtype)

        if self.aes_key is not None:
            send_data = aes_encrypt(message, self.aes_key)
        else:
            send_data = message

        bodysize = struct.pack(">i", len(send_data))
        packet = magic + _msgtype + bodysize + send_data

        return packet

    async def login(self):
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
        self.writer.write(self.getSendPacket(json.dumps(message).encode(), 1))
        await self.writer.drain()

        data = await self.reader.read(1024)
        data_len = len(data)
        if data_len <= 0:
            return

        magic, msgtype, bodysize = struct.unpack(">HHI", data[:8])
        encrypted_data = data[8:]
        if self.aes_key is not None:
            decrypted_data = aes_decrypt(encrypted_data, self.aes_key)
        else:
            decrypted_data = encrypted_data

        json_data = json.loads(decrypted_data)

        self.ascNumber = json_data[CONF_PAYLOAD][CONF_ASCNUMBER]
        self.ascNumber += 1
        self.status.online = True
        await self.sendAction({}, "getDevAttrReq")

    async def read_status(self):
        if self._connect_and_login is False:
            raise AidotNotLogin
        try:
            data = await self.reader.read(1024)
        except BrokenPipeError as e:
            _LOGGER.error(f"{self.device_id} read_statuserror {e}")
        except ConnectionResetError as e:
            _LOGGER.error(f"{self.device_id} read_status error {e}")
        except Exception as e:
            _LOGGER.error(f"recv data error {e}")
            return self.status
        data_len = len(data)
        if data_len <= 0:
            return self.status
        try:
            magic, msgtype, bodysize = struct.unpack(">HHI", data[:8])
            decrypted_data = aes_decrypt(data[8:], self.aes_key)
            json_data = json.loads(decrypted_data)
        except Exception as e:
            _LOGGER.error(f"recv json error : {e}")
            return self.status

        if "service" in json_data:
            if "test" == json_data["service"]:
                self.ping_count = 0
        payload = json_data.get(CONF_PAYLOAD)
        if payload is not None:
            self.ascNumber = payload.get(CONF_ASCNUMBER)
            self.status.update(payload.get(CONF_ATTR))
        return self.status

    async def ping_task(self):
        while True:
            await asyncio.sleep(
                5
            )  # 加个延迟，不然遇到查状态和发ping同时出现状态回不来，暂时不知道什么原因
            if await self.sendPingAction() == -1:
                return
            await asyncio.sleep(5)

    def getOnOffAction(self, OnOff):
        self._is_on = OnOff
        return {CONF_ON_OFF: self._is_on}

    def getDimingAction(self, brightness):
        self._dimming = int(brightness * 100 / 255)
        return {CONF_DIMMING: self._dimming}

    def getCCTAction(self, cct):
        self._cct = cct
        self._color_mode = Attribute.CCT
        return {CONF_CCT: self._cct}

    def getRGBWAction(self, rgbw):
        self._rgdb = rgbw
        self._color_mode = Attribute.RGBW
        return {CONF_RGBW: rgbw}

    async def sendDevAttr(self, devAttr):
        await self.sendAction(devAttr, "setDevAttrReq")

    async def async_turn_off(self) -> None:
        await self.sendDevAttr({CONF_ON_OFF: 0})

    async def sendAction(self, attr, method):
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
            self.writer.write(self.getSendPacket(json.dumps(action).encode(), 1))
            await self.writer.drain()
        except BrokenPipeError as e:
            _LOGGER.error(f"{self.device_id} send action error {e}")
        except Exception as e:
            _LOGGER.error(f"{self.device_id} send action error {e}")

    async def sendPingAction(self):
        ping = {
            "service": "test",
            "method": "pingreq",
            "seq": "123456",
            "srcAddr": "x.xxxxxxx",
            CONF_PAYLOAD: {},
        }
        try:
            if self.ping_count >= 2:
                _LOGGER.error(
                    f"Last ping did not return within 20 seconds. device id:{self.device_id}"
                )
                await self.reset()
                return -1
            self.writer.write(self.getSendPacket(json.dumps(ping).encode(), 2))
            await self.writer.drain()
            self.ping_count += 1
            return 1
        except Exception as e:
            _LOGGER.error(f"{self.device_id} ping error {e}")
            await self.reset()
            return -1

    async def reset(self):
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception as e:
            _LOGGER.error(f"{self.device_id} writer close error {e}")
        self._connect_and_login = False
        self.status.online = False
        self.ping_count = 0
