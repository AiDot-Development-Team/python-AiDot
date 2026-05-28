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

    ssidName: str = ""
    ipAddress: str = ""
    macAddress: str = ""
    networkRssi: str = ""
    networkSecurity: str = ""
    wifiChannel: str = ""
    OnOff: str = ""
    Dimming: str = ""
    CCT: str = ""
    RGBW: str = ""
    EffectMode: str = ""
    Area: str = ""
    city: str = ""
    CityTimezone: str = ""
    lastNotifyCctRgbw: str = ""


@dataclass
class AllowedValue:
    """Allowed value for property."""

    name: str = ""
    description: str = ""
    value: Any = None


@dataclass
class ServiceProperty:
    """Service module property."""

    identity: str = ""
    code: str = ""
    name: str = ""
    description: str = ""
    rwStatus: str = ""
    valueType: str = ""
    ifttt: List[str] = field(default_factory=list)
    allowedValues: List[AllowedValue] = field(default_factory=list)
    maxValue: str = ""
    minValue: str = ""
    step: Optional[str] = None
    dpId: int = 0
    defaultValue: str = ""
    unit: str = ""
    observable: bool = False
    writeOnly: bool = False
    readOnly: bool = False
    paramValueType: Optional[int] = None


@dataclass
class ServiceModule:
    """Service module."""

    identity: str = ""
    properties: List[ServiceProperty] = field(default_factory=list)
    events: List[Any] = field(default_factory=list)
    actions: List[Any] = field(default_factory=list)


@dataclass
class DeviceProduct:
    """Device product info."""

    id: str = ""
    name: str = ""
    version: Optional[str] = None
    apName: str = ""
    type: str = ""
    categoryId: str = ""
    typeId: str = ""
    modelId: str = ""
    picture: str = ""
    icon: str = ""
    isDirectDevice: int = 0
    modelIdMd5: str = ""
    macSpell: str = ""
    powerType: int = 0
    otaWakeUpTime: Optional[int] = None
    otaTouchWakeUp: int = 0
    serviceModules: List[ServiceModule] = field(default_factory=list)
    modelName: Optional[str] = None
    protocolVersion: str = ""
    thingVersion: str = ""
    powerSupplyType: int = 0
    supportThen: List[str] = field(default_factory=list)
    matterEnable: int = 0


@dataclass
class DeviceModel:
    """Device information."""

    id: str = ""
    name: str = ""
    mac: str = ""
    type: str = ""
    modelId: str = ""
    productId: str = ""
    houseId: str = ""
    roomId: str = ""
    online: bool = False
    firmwareVersion: str = ""
    hardwareVersion: Optional[str] = None
    protocolVersion: str = ""
    picture: str = ""
    aesKey: List[str] = field(default_factory=list)
    password: str = ""
    fading: Optional[DeviceFading] = field(default_factory=DeviceFading)
    properties: Optional[DeviceProperties] = field(default_factory=DeviceProperties)
    product: Optional[DeviceProduct] = field(default_factory=DeviceProduct)
    # Additional fields from metadata
    icon: str = ""
    serviceFlag: int = 0
    bleMeshDeviceKey: Optional[str] = None
    directId: str = ""
    slaveSupport: bool = False
    bleMeshAddr: Optional[str] = None
    directGateway: str = ""
    controlFlag: int = 0
    accessFlag: int = 0
    bleMeshDeviceUuid: Optional[str] = None
    share: bool = False
    bleMeshDeviceIndex: Optional[int] = None
    simpleVersion: Optional[str] = None
    ota: Optional[Any] = None
    matterAddr: Optional[str] = None
    groupGateway: int = 0
    chatGPTSupport: bool = False
    powerLow: bool = False
    bleMeshProtocolVersion: Optional[str] = None
    p2pId: Optional[str] = None
    onlineStatusTime: str = ""
    parentId: str = ""
    endPointType: int = 0
    aiBotSupport: bool = False
    favorite: bool = False
    backgroundPicture: Optional[str] = None
    thingVersion: Optional[str] = None

    @staticmethod
    def from_json(data: dict[str, Any]) -> "DeviceModel":
        """Create DeviceModel from JSON dict."""
        return from_dict(
            data_class=DeviceModel, data=data, config=Config(check_types=False)
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
