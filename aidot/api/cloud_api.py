"""Cloud API for AiDot HTTP requests."""

from collections.abc import Callable
import logging
from typing import Any

import aiohttp
from aiohttp import ClientSession

from ..const import (
    API_URL_TEMPLATE,
    CONF_ACCESS_TOKEN,
    CONF_CODE,
    CONF_REFRESH_TOKEN,
    ServerErrorCode,
)
from ..exceptions import AidotAuthFailed, AidotUserOrPassIncorrect
from ..models.auth_model import RequestHeaders, UserInformation

_LOGGER = logging.getLogger(__name__)


class CloudApi:
    """Cloud API client scoped to one AiDot account."""

    def __init__(
        self,
        session: ClientSession,
        user_info: UserInformation,
        auth_failed_callback: Callable[[], None] | None = None,
        token_refreshed_callback: Callable[[], None] | None = None,
    ) -> None:
        """Initialize an account-scoped Cloud API client."""
        self._session = session
        self._user_info = user_info
        self._base_url = API_URL_TEMPLATE.format(region=user_info.region)
        self._auth_failed_callback = auth_failed_callback
        self._token_refreshed_callback = token_refreshed_callback

    def _get_headers(self) -> dict[str, str]:
        """Build request headers with access token."""
        return RequestHeaders.create(self._user_info.accessToken)

    async def login(self, data: dict[str, Any]) -> dict[str, Any]:
        """Login and return tokens."""
        url = f"{self._base_url}/users/loginWithFreeVerification"
        headers = self._get_headers()

        response_data = {}
        try:
            _LOGGER.info("POST %s body=%s", url, data)
            response = await self._session.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()
            _LOGGER.info("POST %s → %s resp=%s", url, response.status, response_data)
            return response_data
        except aiohttp.ClientError as e:
            _LOGGER.error(f"login failed: {e} resp={response_data}")
            if response_data.get(CONF_CODE) == ServerErrorCode.USER_PWD_INCORRECT:
                raise AidotUserOrPassIncorrect
            raise Exception

    async def refresh_token(self) -> dict[str, Any]:
        """Refresh access token."""
        url = f"{self._base_url}/users/refreshToken"
        headers = self._get_headers()
        data = {
            CONF_REFRESH_TOKEN: self._user_info.refreshToken,
        }

        response_data = {}
        try:
            _LOGGER.info("POST %s body=%s", url, data)
            response = await self._session.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()

            # Update tokens and notify
            self._user_info.accessToken = response_data.get(CONF_ACCESS_TOKEN, "")
            if response_data.get(CONF_REFRESH_TOKEN) is not None:
                self._user_info.refreshToken = response_data[CONF_REFRESH_TOKEN]

            # Notify callback
            if self._token_refreshed_callback:
                self._token_refreshed_callback()

            _LOGGER.info("Token refreshed: %s", response_data)
            return response_data
        except aiohttp.ClientError as e:
            _LOGGER.error(f"refresh_token failed: {e} resp={response_data}")
            code = response_data.get(CONF_CODE)
            if code == ServerErrorCode.LOGIN_INVALID or code in (21027, 21041):
                raise AidotAuthFailed
            return None

    async def get(self, params: str) -> dict[str, Any]:
        """GET request with auto token refresh on 401."""
        url = f"{self._base_url}{params}"
        headers = self._get_headers()

        response_data = {}
        try:
            _LOGGER.info("GET %s", url)
            response = await self._session.get(url, headers=headers)
            response_data = await response.json()
            response.raise_for_status()
            _LOGGER.info("GET %s → %s", url, response.status)
            return response_data
        except aiohttp.ClientError as e:
            _LOGGER.error(f"GET {params} failed: {e} resp={response_data}")
            code = response_data.get(CONF_CODE)
            if code == ServerErrorCode.TOKEN_EXPIRED:
                try:
                    refresh_data = await self.refresh_token()
                    if refresh_data:
                        _LOGGER.info("Retrying GET %s", url)
                        headers = self._get_headers()
                        response = await self._session.get(url, headers=headers)
                        response_data = await response.json()
                        response.raise_for_status()
                        _LOGGER.info("GET %s → %s retry=ok", url, response.status)
                        return response_data
                except AidotAuthFailed:
                    if self._auth_failed_callback:
                        self._auth_failed_callback()
                    raise
                except Exception as refresh_error:
                    _LOGGER.error(f"Token refresh failed: {refresh_error}")
                    if self._auth_failed_callback:
                        self._auth_failed_callback()
                    raise AidotAuthFailed
            elif code in (ServerErrorCode.LOGIN_INVALID, 21027, 21041):
                if self._auth_failed_callback:
                    self._auth_failed_callback()
                raise AidotAuthFailed
            raise

    async def get_products(self, product_ids: str) -> list[dict[str, Any]]:
        """Get products by comma-separated IDs."""
        params = f"/products/{product_ids}"
        return await self.get(params)

    async def get_devices(self, house_id: str) -> list[dict[str, Any]]:
        """Get devices in a house."""
        params = f"/devices?houseId={house_id}"
        return await self.get(params)

    async def get_houses(self) -> list[dict[str, Any]]:
        """Get all houses for the user."""
        params = "/houses"
        return await self.get(params)
