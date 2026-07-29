"""Models for AiDot."""

from .device_client_model import (
    DeviceAck,
    DeviceAttr,
    DeviceAttrPayload,
    DeviceResponse,
    DeviceActionPayload,
    DeviceActionRequest,
    LoginPayload,
    LoginRequest,
    PingRequest,
    PingResponse,
)
from .device_model import (
    DeviceFading,
    DeviceProperties,
    DeviceProduct,
    DeviceInformation,
)

__all__ = [
    "DeviceAck",
    "DeviceAttr",
    "DeviceAttrPayload",
    "DeviceResponse",
    "DeviceActionPayload",
    "DeviceActionRequest",
    "LoginPayload",
    "LoginRequest",
    "PingRequest",
    "PingResponse",
    "DeviceFading",
    "DeviceProperties",
    "DeviceProduct",
    "DeviceInformation",
]
