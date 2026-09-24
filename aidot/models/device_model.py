"""Models for AiDot device."""

from dataclasses import dataclass, asdict, field
from typing import Any, Optional, List

from dacite import Config, from_dict


@dataclass
class DeviceFading:
    """Device fading config."""

    in_value: Optional[int] = field(default=None, metadata={"alias": "in"})
    out: Optional[int] = None


@dataclass
class DeviceProperties:
    """Device properties."""

    ssidName: str = None
    ipAddress: str = None
    macAddress: str = None
    networkRssi: str = None
    networkSecurity: str = None
    wifiChannel: str = None
    OnOff: str = None
    Dimming: str = None
    CCT: str = None
    RGBW: str = None
    EffectMode: str = None
    Area: str = None
    city: str = None
    CityTimezone: str = None
    lastNotifyCctRgbw: str = None


@dataclass
class DeviceProduct:
    """Device product info."""

    id: str = None
    name: str = None
    type: str = None
    modelId: str = None
    picture: str = None
    icon: str = None
    isDirectDevice: int = None


@dataclass
class DeviceInformation:
    """Device information."""

    id: str = None
    name: str = None
    mac: str = None
    type: str = None
    modelId: str = None
    productId: str = None
    houseId: str = None
    roomId: str = None
    online: bool = None
    firmwareVersion: str = None
    hardwareVersion: str = None
    protocolVersion: str = None
    picture: str = None
    aesKey: List[str] = field(default_factory=list)
    password: str = None
    fading: Optional[DeviceFading] = None
    properties: Optional[DeviceProperties] = None
    product: Optional[DeviceProduct] = None

    @staticmethod
    def from_json(data: dict[str, Any]) -> "DeviceInformation":
        """Create DeviceInformation from JSON dict."""
        return from_dict(
            data_class=DeviceInformation, data=data, config=Config(check_types=False)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class FavoriteEffectTags:
    """Favorite effect tags."""

    advanced: str = None
    directional: str = None


@dataclass
class FavoriteEffectPrimitive:
    """Favorite primitive effect mode."""

    primitiveEffectId: str = None
    favoriteId: str = None
    icon: str = None
    libraryId: str = "aidot.preset"
    name: str = None
    tag: str = None
    tags: Optional[FavoriteEffectTags] = None
    scriptSize: int = None
    secondShareFlag: bool = None
    changeFlag: bool = None
    createTime: int = None
    imageUrl: str = None
    videoUrl: str = None
    sharedUserName: str = None
    sharedUserHeadImg: str = None
    sharedTime: int = None
    shareId: str = None
    isOldParams: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class FavoriteEffectMode:
    """Favorite effect mode response."""

    data: list[Any] = field(default_factory=list)
    primitive: list[FavoriteEffectPrimitive] = field(default_factory=list)

    @staticmethod
    def from_json(data: dict[str, Any]) -> "FavoriteEffectMode":
        """Create FavoriteEffectMode from JSON dict."""
        return from_dict(
            data_class=FavoriteEffectMode, data=data, config=Config(check_types=False)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


EffectResp = FavoriteEffectMode
