"""Models for AiDot device client."""

import time
from dataclasses import dataclass, field
from typing import Any, Optional
from .base_model import BaseModel
from .device_model import DeviceModel


class DeviceProtocol:
    """Device protocol constants."""

    # Service types
    SERVICE_DEVICE = "device"
    SERVICE_TEST = "test"

    # Method types
    METHOD_LOGIN_REQ = "loginReq"
    METHOD_PING_REQ = "pingreq"
    METHOD_GET_DEV_ATTR_REQ = "getDevAttrReq"
    METHOD_SET_DEV_ATTR_REQ = "setDevAttrReq"

    # Msg types
    MSG_TYPE_DATA = 1  # 业务数据
    MSG_TYPE_HEARTBEAT = 2  # 心跳包


@dataclass
class BaseRequest(BaseModel):
    """Base request with common fields."""

    service: str = ""
    method: str = ""
    seq: str = ""
    srcAddr: str = ""
    payload: Any = None


@dataclass
class PingRequest(BaseRequest):
    """Ping request (heartbeat)."""

    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Set default values for inherited fields."""
        self.service = DeviceProtocol.SERVICE_TEST
        self.method = DeviceProtocol.METHOD_PING_REQ
        self.seq = "123456"
        self.srcAddr = "123456"


@dataclass
class PingResponse(BaseModel):
    """Ping response."""

    service: Optional[str] = None
    method: Optional[str] = None
    seq: Optional[str] = None
    srcAddr: Optional[str] = None
    payload: Optional[dict[str, Any]] = None


@dataclass
class LoginPayload(BaseModel):
    """Login request payload."""

    userId: Optional[str] = None
    password: Optional[str] = None
    timestamp: Optional[str] = None
    ascNumber: int = 1

    def __post_init__(self) -> None:
        """Auto-generate timestamp if not provided."""
        if self.timestamp is None:
            from datetime import datetime

            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")


@dataclass
class LoginRequest(BaseRequest):
    """Login request."""

    deviceId: Optional[str] = None

    def __init__(self, device: DeviceModel, user_id: str) -> None:
        self.service = DeviceProtocol.SERVICE_DEVICE
        self.method = DeviceProtocol.METHOD_LOGIN_REQ
        self.seq = str(int(time.time() * 1000))[-9:]
        self.srcAddr = user_id
        self.deviceId = device.id
        self.payload = LoginPayload(
            userId=user_id,
            password=device.password,
        )


@dataclass
class DeviceAck(BaseModel):
    """Device response ack."""

    code: int = 0
    tst: str = ""


@dataclass
class DeviceAttr(BaseModel):
    """Device attribute."""

    OnOff: Optional[int] = None
    Dimming: Optional[int] = None
    RGBW: Optional[int] = None
    CCT: Optional[int] = None


@dataclass
class DeviceAttrPayload(BaseModel):
    """Device payload."""

    devId: str = ""
    parentId: str = ""
    userId: str = ""
    password: str = ""
    timestamp: str = ""
    channel: str = ""
    ascNumber: int = 0
    attr: Optional[DeviceAttr] = None


@dataclass
class DeviceResponse(BaseModel):
    """Generic device response."""

    service: str = ""
    method: str = ""
    seq: str = ""
    srcAddr: str = ""
    deviceId: str = ""
    clientId: str = ""
    payload: DeviceAttrPayload = field(default_factory=DeviceAttrPayload)
    ack: DeviceAck = field(default_factory=DeviceAck)
    tst: int = 0


@dataclass
class DeviceActionPayload(BaseModel):
    """Device action payload."""

    devId: str = ""
    parentId: str = ""
    userId: str = ""
    password: str = ""
    attr: dict[str, Any] = field(default_factory=dict)
    channel: str = "tcp"
    ascNumber: int = 0


@dataclass
class DeviceActionRequest(BaseRequest):
    """Device action request."""

    clientId: str = ""
    tst: int = 0
    deviceId: str = ""

    def __post_init__(self) -> None:
        """Set default values for inherited fields."""
        self.service = DeviceProtocol.SERVICE_DEVICE
        if self.tst == 0:
            self.tst = int(time.time() * 1000)

    @staticmethod
    def from_params(
        method: str,
        user_id: str,
        device: DeviceModel,
        ascNumber: int,
        attr: dict[str, Any],
        seq: str,
    ) -> "DeviceActionRequest":
        """Create DeviceActionRequest from params."""
        if device.simpleVersion is not None:
            return DeviceActionRequest(
                method=method,
                clientId="ha-" + user_id,
                srcAddr="0." + user_id,
                seq=seq,
                payload=DeviceActionPayload(
                    devId=device.id,
                    parentId=device.id,
                    userId=user_id,
                    password=device.password,
                    attr=attr,
                    ascNumber=ascNumber,
                ),
                deviceId=device.id,
            )
        else:
            return DeviceActionRequest(
                method=method,
                srcAddr="0." + user_id,
                seq=seq,
                payload=DeviceActionPayload(
                    attr=attr,
                    ascNumber=ascNumber,
                ),
                deviceId=device.id,
            )
