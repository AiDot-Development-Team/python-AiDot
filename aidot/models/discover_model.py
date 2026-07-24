"""Models for AiDot discover."""

import time
from dataclasses import dataclass, asdict, field
from typing import Any, Optional

from dacite import Config, from_dict


@dataclass
class DiscoverAck:
    """Discover response ack."""

    code: int = None
    tst: str = None


@dataclass
class DiscoverExtends:
    """Discover payload extends."""

    srvHost: str = None


@dataclass
class DiscoverPayload:
    """Discover response payload."""

    ip: str = None
    mac: str = None
    devId: str = None
    productModel: str = None
    bindFlag: int = None
    conMode: int = None
    lanMode: int = None
    wifiMode: int = None
    wifiBand: int = None
    version: int = None
    extends: Optional[DiscoverExtends] = None


@dataclass
class DiscoverResponse:
    """Discover device response."""

    srcAddr: str = None
    seq: str = None
    service: str = None
    method: str = None
    ack: DiscoverAck = None
    protocolVer: str = None
    payload: DiscoverPayload = None

    @staticmethod
    def from_json(data: dict[str, Any]) -> "DiscoverResponse":
        """Create DiscoverResponse from JSON dict."""
        return from_dict(
            data_class=DiscoverResponse, data=data, config=Config(check_types=False)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DiscoverRequestPayload:
    """Discover request payload."""

    extends: dict[str, Any] = field(default_factory=dict)
    localCtrFlag: int = 1
    timestamp: str = None


@dataclass
class DiscoverRequest:
    """Discover device request."""

    protocolVer: str = "2.0.0"
    service: str = "device"
    method: str = "devDiscoveryReq"
    seq: str = None
    srcAddr: str = None
    tst: int = None
    payload: DiscoverRequestPayload = field(default_factory=DiscoverRequestPayload)

    @staticmethod
    def from_params(userId: str) -> "DiscoverResponse":
        """Create DiscoverResponse from JSON dict."""
        current_timestamp_milliseconds = int(time.time() * 1000)
        seq = str(current_timestamp_milliseconds + 1)[-9:]
        return DiscoverRequest(
            seq=seq,
            srcAddr=f"0.{userId}",
            tst=current_timestamp_milliseconds,
            payload=DiscoverRequestPayload(
                timestamp=str(current_timestamp_milliseconds)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
