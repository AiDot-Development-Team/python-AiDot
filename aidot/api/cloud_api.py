"""Cloud API for AiDot - static class for HTTP requests."""

import logging
from typing import Any, Optional
import aiohttp
from aiohttp import ClientSession

from ..const import (
    API_URL_TEMPLATE,
    CONF_ACCESS_TOKEN,
    CONF_CODE,
    CONF_REFRESH_TOKEN,
    ServerErrorCode,
)
from ..exceptions import (
    AidotAuthFailed,
    AidotAuthTokenExpired,
    AidotUserOrPassIncorrect,
)
from ..models.auth_model import RequestHeaders, UserInformation

_LOGGER = logging.getLogger(__name__)


class CloudApi:
    """Cloud API - static class for HTTP requests."""

    BASE_URL: str = ""
    SESSION: Optional[ClientSession] = None
    USER_INFO: Optional[UserInformation] = None
    _auth_failed_callback: Optional[callable] = None
    _token_refreshed_callback: Optional[callable] = None

    def __init__(self) -> None:
        raise TypeError("CloudApi is a static class and cannot be instantiated")

    @classmethod
    def set_session(cls, session: ClientSession) -> None:
        """Set the HTTP session."""
        cls.SESSION = session

    @classmethod
    def set_user_info(cls, user_info: "UserInformation") -> None:
        """Set user info and update base URL."""
        cls.USER_INFO = user_info
        cls.BASE_URL = API_URL_TEMPLATE.format(region=user_info.region)

    @classmethod
    def set_auth_failed_callback(cls, callback: callable) -> None:
        """Set auth failure callback."""
        cls._auth_failed_callback = callback

    @classmethod
    def set_token_refreshed_callback(cls, callback: callable) -> None:
        """Set token refresh callback."""
        cls._token_refreshed_callback = callback

    @classmethod
    def _get_headers(cls) -> dict[str, str]:
        """Build request headers with access token."""
        access_token = cls.USER_INFO.accessToken if cls.USER_INFO else None
        return RequestHeaders.create(access_token)

    @classmethod
    async def login(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Login and return tokens."""
        url = f"{cls.BASE_URL}/users/loginWithFreeVerification"
        headers = cls._get_headers()

        response_data = {}
        try:
            _LOGGER.info("POST %s body=%s", url, data)
            response = await cls.SESSION.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()
            _LOGGER.info("POST %s → %s resp=%s", url, response.status, response_data)
            return response_data
        except aiohttp.ClientError as e:
            _LOGGER.error(f"login failed: {e} resp={response_data}")
            if response_data.get(CONF_CODE) == ServerErrorCode.USER_PWD_INCORRECT:
                raise AidotUserOrPassIncorrect
            raise Exception

    @classmethod
    async def refresh_token(cls) -> dict[str, Any]:
        """Refresh access token."""
        if cls.USER_INFO is None:
            raise AidotAuthFailed("No user info available")

        url = f"{cls.BASE_URL}/users/refreshToken"
        headers = cls._get_headers()
        data = {
            CONF_REFRESH_TOKEN: cls.USER_INFO.refreshToken,
        }

        response_data = {}
        try:
            _LOGGER.info("POST %s body=%s", url, data)
            response = await cls.SESSION.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()

            # Update tokens and notify
            cls.USER_INFO.accessToken = response_data.get(CONF_ACCESS_TOKEN, "")
            if response_data.get(CONF_REFRESH_TOKEN) is not None:
                cls.USER_INFO.refreshToken = response_data[CONF_REFRESH_TOKEN]

            # Notify callback
            if cls._token_refreshed_callback:
                cls._token_refreshed_callback()

            _LOGGER.info("Token refreshed: %s", response_data)
            return response_data
        except aiohttp.ClientError as e:
            _LOGGER.error(f"refresh_token failed: {e} resp={response_data}")
            code = response_data.get(CONF_CODE)
            if code == ServerErrorCode.LOGIN_INVALID or code in (21027, 21041):
                raise AidotAuthFailed
            return None

    @classmethod
    async def get(cls, params: str) -> dict[str, Any]:
        """GET request with auto token refresh on 401."""
        url = f"{cls.BASE_URL}{params}"
        headers = cls._get_headers()

        response_data = {}
        try:
            _LOGGER.info("GET %s", url)
            response = await cls.SESSION.get(url, headers=headers)
            response_data = await response.json()
            response.raise_for_status()
            _LOGGER.info("GET %s → %s", url, response.status)
            return response_data
        except aiohttp.ClientError as e:
            _LOGGER.error(f"GET {params} failed: {e} resp={response_data}")
            code = response_data.get(CONF_CODE)
            if code == ServerErrorCode.TOKEN_EXPIRED:
                try:
                    refresh_data = await cls.refresh_token()
                    if refresh_data:
                        _LOGGER.info("Retrying GET %s", url)
                        headers = cls._get_headers()
                        response = await cls.SESSION.get(url, headers=headers)
                        response_data = await response.json()
                        response.raise_for_status()
                        _LOGGER.info("GET %s → %s retry=ok", url, response.status)
                        return response_data
                except AidotAuthFailed:
                    if cls._auth_failed_callback:
                        cls._auth_failed_callback()
                    raise
                except Exception as refresh_error:
                    _LOGGER.error(f"Token refresh failed: {refresh_error}")
                    if cls._auth_failed_callback:
                        cls._auth_failed_callback()
                    raise AidotAuthFailed
            elif code in (ServerErrorCode.LOGIN_INVALID, 21027, 21041):
                if cls._auth_failed_callback:
                    cls._auth_failed_callback()
                raise AidotAuthFailed
            raise

    @classmethod
    async def get_products(cls, product_ids: str) -> list[dict[str, Any]]:
        """Get products by comma-separated IDs."""
        params = f"/products/{product_ids}"
        return await cls.get(params)

    @classmethod
    async def get_devices(cls, house_id: str) -> list[dict[str, Any]]:
        """Get devices in a house."""
        params = f"/devices?houseId={house_id}"
        return await cls.get(params)

    @classmethod
    async def get_houses(cls) -> list[dict[str, Any]]:
        """Get all houses for the user."""
        params = "/houses"
        return await cls.get(params)
