"""The aidot integration."""

import asyncio
import logging
import base64
import aiohttp
from aiohttp import ClientSession
from typing import Any, Optional
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .exceptions import AidotAuthFailed, AidotUserOrPassIncorrect
from .device_client import DeviceClient
from .discover import Discover
from .login_const import APP_ID, PUBLIC_KEY_PEM, BASE_URL
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_APP_ID,
    CONF_CODE,
    CONF_COUNTRY,
    CONF_DEVICE_LIST,
    CONF_ID,
    CONF_IPADDRESS,
    CONF_PASSWORD,
    CONF_PRODUCT,
    CONF_PRODUCT_ID,
    CONF_REFRESH_TOKEN,
    CONF_REGION,
    CONF_TERMINAL,
    CONF_TOKEN,
    CONF_USERNAME,
    DEFAULT_COUNTRY_NAME,
    SUPPORTED_COUNTRYS,
    ServerErrorCode,
)

_LOGGER = logging.getLogger(__name__)


def rsa_password_encrypt(message: str) -> str:
    """Get password rsa encrypt."""
    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY_PEM, backend=default_backend()
    )

    encrypted = public_key.encrypt(
        message.encode("utf-8"),
        padding.PKCS1v15(),
    )

    encrypted_base64 = base64.b64encode(encrypted).decode("utf-8")
    return encrypted_base64


class AidotClient:
    _base_url: str = BASE_URL
    _region: str = "us"
    session: Optional[ClientSession] = None
    username: str = ""
    password: str = ""
    country_name: str = DEFAULT_COUNTRY_NAME
    login_info: dict[str, Any] = {}
    _device_clients: dict[str, DeviceClient]
    _discover: Discover = None

    def __init__(
        self,
        session: Optional[ClientSession],
        country_name: str | None = None,
        username: str | None = None,
        password: str | None = None,
        token: dict | None = None,
    ) -> None:
        self.session = session
        self.country_name = country_name
        self.username = username
        self.password = password
        self._device_clients = {}
        for item in SUPPORTED_COUNTRYS:
            if item["name"] == self.country_name:
                self._region = item["region"].lower()
                self._base_url = f"https://prod-{self._region}-api.arnoo.com/v17"
                break
        if token is not None:
            self.login_info = token.copy()
            self.username = token[CONF_USERNAME]
            self.password = token[CONF_PASSWORD]
            self._region = token[CONF_REGION]
            self.country_name = token[CONF_COUNTRY]

    def set_token_fresh_cb(self, callback) -> None:
        self._token_fresh_cb = callback

    def get_identifier(self) -> str:
        return f"{self._region}-{self.username}"

    def update_password(self, password: str) -> None:
        self.password = password

    async def async_post_login(self) -> dict[str, Any]:
        """Login the user input allows us to connect."""
        url = f"{self._base_url}/users/loginWithFreeVerification"
        headers = {CONF_APP_ID: APP_ID, CONF_TERMINAL: "app"}
        data = {
            "countryKey": "region:UnitedStates",
            "username": self.username,
            "password": rsa_password_encrypt(self.password),
            "terminalId": "gvz3gjae10l4zii00t7y0",
            "webVersion": "0.5.0",
            "area": "Asia/Shanghai",
            "UTC": "UTC+8",
        }

        try:
            response = await self.session.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()
            self.login_info = response_data
            self.login_info[CONF_PASSWORD] = self.password
            self.login_info[CONF_REGION] = self._region
            self.login_info[CONF_COUNTRY] = self.country_name
            return self.login_info
        except aiohttp.ClientError as e:
            _LOGGER.info(f"async_post_login ClientError {e}")
            if response_data[CONF_CODE] == ServerErrorCode.USER_PWD_INCORRECT:
                raise AidotUserOrPassIncorrect
            raise Exception

    async def async_refresh_token(self) -> dict[str, Any]:
        url = f"{self._base_url}/users/refreshToken"
        headers = {CONF_APP_ID: APP_ID, CONF_TERMINAL: "app"}
        data = {
            CONF_REFRESH_TOKEN: self.login_info[CONF_REFRESH_TOKEN],
        }

        try:
            response = await self.session.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()
            self.login_info[CONF_ACCESS_TOKEN] = response_data[CONF_ACCESS_TOKEN]
            if response_data[CONF_REFRESH_TOKEN] is not None:
                self.login_info[CONF_REFRESH_TOKEN] = response_data[CONF_REFRESH_TOKEN]
            _LOGGER.info(f"refresh token {response_data}")
            if self._token_fresh_cb:
                self._token_fresh_cb()
            return response_data
        except aiohttp.ClientError as e:
            _LOGGER.info(f"async_refresh_token ClientError {e}")
            if response_data[CONF_CODE] == ServerErrorCode.LOGIN_INVALID:
                raise AidotAuthFailed
            return None

    async def async_session_get(
        self, params: str, headers: str | None = None
    ) -> dict[str, Any]:
        url = f"{self._base_url}{params}"
        token = self.login_info[CONF_ACCESS_TOKEN]
        if token is None:
            raise AidotAuthFailed()
        if headers is None:
            headers = {
                CONF_TERMINAL: "app",
                CONF_TOKEN: token,
                CONF_APP_ID: APP_ID,
            }
        response_data = {}
        try:
            response = await self.session.get(url, headers=headers)
            response_data = await response.json()
            response.raise_for_status()
            return response_data
        except aiohttp.ClientError as e:
            _LOGGER.info(f"async_get ClientError {e}")
            code = response_data.get(CONF_CODE)
            if code == ServerErrorCode.TOKEN_EXPIRED:
                try:
                    await self.async_refresh_token()
                    return await self.async_session_get(params)
                except AidotAuthFailed:
                    raise AidotAuthFailed
            elif (
                code == ServerErrorCode.LOGIN_INVALID or code == 21027 or code == 21041
            ):
                self.login_info[CONF_ACCESS_TOKEN] = None
                raise AidotAuthFailed
            return aiohttp.ClientError

    async def async_get_products(self, product_ids: str) -> list[dict[str, Any]]:
        """Get device list."""
        params = f"/products/{product_ids}"
        return await self.async_session_get(params)

    async def async_get_devices(self, house_id: str) -> list[dict[str, Any]]:
        """Get device list."""
        params = f"/devices?houseId={house_id}"
        return await self.async_session_get(params)

    async def async_get_houses(self) -> list[dict[str, Any]]:
        """Get house list."""
        params = "/houses"
        return await self.async_session_get(params)

    async def async_get_all_device(self) -> dict[str, Any]:
        final_device_list: list[dict[str, Any]] = []
        try:
            houses = await self.async_get_houses()
            for house in houses:
                # get device_list
                device_list = await self.async_get_devices(house[CONF_ID])
                if device_list:
                    final_device_list.extend(device_list)

            # get product_list
            productIds = ",".join([item[CONF_PRODUCT_ID] for item in final_device_list])
            product_list = await self.async_get_products(productIds)

            for product in product_list:
                for device in final_device_list:
                    if device[CONF_PRODUCT_ID] == product[CONF_ID]:
                        device[CONF_PRODUCT] = product
        except Exception as e:
            raise e
        return {CONF_DEVICE_LIST: final_device_list}

    def get_device_client(self, device: dict[str, Any]) -> DeviceClient:
        device_id = device.get(CONF_ID)
        device_client: DeviceClient = self._device_clients.get(device_id)
        if device_client is None:
            device_client = DeviceClient(device, self.login_info)
            self._device_clients[device_id] = device_client
            asyncio.get_running_loop().create_task(device_client.ping_task())
        if self._discover is not None:
            ip = self._discover.discovered_device.get(device_id)
            device_client.update_ip_address(ip)
        return device_client

    async def remove_device_client(self, dev_id: str) -> None:
        device_client: DeviceClient = self._device_clients.get(dev_id)
        if device_client is not None:
            await device_client.close()
            del self._device_clients[dev_id]

    def start_discover(self) -> None:
        if self._discover is not None:
            return

        def _discover_callback(dev_id, event: dict[str, str]) -> None:
            device_ip = event[CONF_IPADDRESS]
            device_client: DeviceClient = self._device_clients.get(dev_id)
            if device_client is not None:
                device_client.update_ip_address(device_ip)

        self._discover = Discover(self.login_info, _discover_callback)
        asyncio.get_running_loop().create_task(self._discover.repeat_broadcast())

    def stop_discover(self) -> None:
        self._discover.close()
        self._discover = None

    def cleanup(self) -> None:
        self.stop_discover()
        for client in self._device_clients.values():
            asyncio.get_running_loop().create_task(client.close())
        self._device_clients.clear()
