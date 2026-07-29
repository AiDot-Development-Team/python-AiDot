"""Models for AiDot device client."""

from dataclasses import dataclass, asdict, field
from typing import Any, Optional

from dacite import Config, from_dict


@dataclass
class PingRequest:
    """Ping request (heartbeat)."""

    service: str = "test"
    method: str = "pingreq"
    seq: str = "123456"
    srcAddr: str = "123456"
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class PingResponse:
    """Ping response."""

    service: str = None
    method: str = None
    seq: str = None
    srcAddr: str = None
    payload: dict[str, Any] = None

    @staticmethod
    def from_json(data: dict[str, Any]) -> "PingResponse":
        """Create PingResponse from JSON dict."""
        return from_dict(
            data_class=PingResponse, data=data, config=Config(check_types=False)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class LoginPayload:
    """Login request payload."""

    userId: str = None
    password: str = None
    timestamp: str = field(default=None)
    ascNumber: int = 1

    def __post_init__(self):
        """Auto-generate timestamp if not provided."""
        if self.timestamp is None:
            from datetime import datetime

            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")


@dataclass
class LoginRequest:
    """Login request."""

    service: str = "device"
    method: str = "loginReq"
    seq: str = None
    srcAddr: str = None
    deviceId: str = None
    payload: LoginPayload = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DeviceAck:
    """Device response ack."""

    code: int = 0
    tst: str = ""


@dataclass
class DeviceAttr:
    """Device attribute."""

    OnOff: int = None
    Dimming: int = None
    RGBW: int = None
    CCT: int = None


@dataclass
class DeviceAttrPayload:
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
class DeviceResponse:
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

    @staticmethod
    def from_json(data: dict[str, Any]) -> "DeviceResponse":
        """Create DeviceResponse from JSON dict."""
        return from_dict(
            data_class=DeviceResponse, data=data, config=Config(check_types=False)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DeviceActionPayload:
    """Device action payload."""

    devId: str = ""
    parentId: str = ""
    userId: str = ""
    password: str = ""
    attr: dict[str, Any] = field(default_factory=dict)
    channel: str = "tcp"
    ascNumber: int = 0


@dataclass
class DeviceActionRequest:
    """Device action request."""

    method: str = ""
    service: str = "device"
    clientId: str = ""
    srcAddr: str = ""
    seq: str = ""
    payload: DeviceActionPayload = field(default_factory=DeviceActionPayload)
    tst: int = 0
    deviceId: str = ""

    def __post_init__(self):
        """Auto-generate timestamp if not provided."""
        if self.tst == 0:
            import time

            self.tst = int(time.time() * 1000)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @staticmethod
    def from_params(
        method: str,
        user_id: str,
        device_id: str,
        password: str,
        ascNumber: int,
        attr: dict[str, Any],
        seq: str,
        simpleVersion: str = None,
    ) -> "DeviceActionRequest":
        """Create DeviceActionRequest from params."""
        if simpleVersion is not None:
            return DeviceActionRequest(
                method=method,
                clientId="ha-" + user_id,
                srcAddr="0." + user_id,
                seq=seq,
                payload=DeviceActionPayload(
                    devId=device_id,
                    parentId=device_id,
                    userId=user_id,
                    password=password,
                    attr=attr,
                    ascNumber=ascNumber,
                ),
                deviceId=device_id,
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
                deviceId=device_id,
            )
