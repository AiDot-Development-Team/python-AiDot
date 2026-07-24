"""Models for AiDot authentication."""

from dataclasses import dataclass, asdict
from typing import Any, Optional

from dacite import Config, from_dict

from ..const import APP_ID


@dataclass
class RequestHeaders:
    """Common request headers for API calls."""

    appId: str = APP_ID
    terminal: str = "app"
    token: Optional[str] = None

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary, excluding None values."""
        result = asdict(self)
        if result["token"] is None:
            del result["token"]
        return result

    @staticmethod
    def create(access_token: Optional[str] = None) -> dict[str, str]:
        """Create headers dict with optional access token.

        Args:
            access_token: Optional access token

        Returns:
            Headers dictionary
        """
        return RequestHeaders(token=access_token).to_dict()


@dataclass
class LoginRequest:
    """Login request payload."""

    countryKey: str
    username: str
    password: str  # RSA encrypted password
    terminalId: str
    webVersion: str = "0.5.0"
    area: str = "Asia/Shanghai"
    UTC: str = "UTC+8"

    @staticmethod
    def create(
        username: str,
        encrypted_password: str,
        country_name: str,
        terminal_id: str,
        area: str = "Asia/Shanghai",
        utc: str = "UTC+8",
    ) -> "LoginRequest":
        """Create a login request with encrypted password.

        Args:
            username: User username
            encrypted_password: RSA encrypted password
            country_name: Country name for region
            terminal_id: Terminal identifier
            area: Area (default: Asia/Shanghai)
            utc: UTC timezone (default: UTC+8)

        Returns:
            LoginRequest instance
        """
        return LoginRequest(
            countryKey=f"region:{country_name.strip()}",
            username=username,
            password=encrypted_password,
            terminalId=terminal_id,
            area=area,
            UTC=utc,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class UserInformation:
    """Authentication response from login API."""

    accessToken: str = ""
    refreshToken: str = ""
    id: str = ""
    username: str = ""
    nickname: str = ""
    email: Optional[str] = None
    phone: Optional[str] = None
    country: str = ""
    country_code: str = ""
    region: str = ""
    locale: str = ""
    expiresIn: int = 7200
    expireTime: int = 0
    activeFlag: bool = False
    tid: str = ""
    terminalIndex: str = ""
    # Optional fields
    avatar: Optional[str] = None
    brandMigrationSign: Optional[Any] = None
    emailVerificationSign: Optional[Any] = None
    initPassword: Optional[str] = None
    secondaryCertificationSign: Optional[Any] = None
    thirdAuthSign: Optional[Any] = None
    thirdEmail: Optional[str] = None
    thirdLoginErr: Optional[Any] = None
    thirdLoginStatus: Optional[Any] = None
    thirdUuid: Optional[str] = None
    url: Optional[str] = None
    # Additional fields for client use (not from API)
    password: str = ""

    @staticmethod
    def from_json(data: dict[str, Any]) -> "UserInformation":
        """Create UserInformation from JSON dict."""
        return from_dict(
            data_class=UserInformation, data=data, config=Config(check_types=False)
        )

    def update_from_json(self, data: dict[str, Any]) -> None:
        """Update fields from JSON dict."""
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class RefreshTokenResponse:
    """Refresh token response."""

    accessToken: str = ""
    refreshToken: Optional[str] = None
    expiresIn: Optional[int] = None

    @staticmethod
    def from_json(data: dict[str, Any]) -> "RefreshTokenResponse":
        """Create RefreshTokenResponse from JSON dict."""
        return from_dict(
            data_class=RefreshTokenResponse, data=data, config=Config(check_types=False)
        )


@dataclass
class House:
    """House information."""

    id: str = ""
    name: str = ""
    isOwner: bool = False
    userId: str = ""
    createTime: Optional[str] = None
    updateTime: Optional[str] = None

    @staticmethod
    def from_json(data: dict[str, Any]) -> "House":
        """Create House from JSON dict."""
        return from_dict(data_class=House, data=data, config=Config(check_types=False))
