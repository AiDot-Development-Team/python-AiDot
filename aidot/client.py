"""The aidot integration."""

import asyncio
import logging
from aiohttp import ClientSession
from typing import Any, Optional
import uuid
from pathlib import Path
import hashlib

from .utils import rsa_encrypt
from .device_client import DeviceClient
from .models.auth_model import UserInformation, LoginRequest
from .models.device_model import DeviceModel
from .api.cloud_api import CloudApi
from .discover import Discover
from .const import PUBLIC_KEY_PEM
from .const import (
    CONF_ID,
    CONF_IPADDRESS,
    CONF_LOGIN_INFO,
    CONF_DEVICE_LIST,
    CONF_PRODUCT,
    CONF_PRODUCT_ID,
    CONF_IS_OWNER,
    SUPPORTED_COUNTRYS,
    CONF_TYPE,
    CONF_AES_KEY,
)

_LOGGER = logging.getLogger(__name__)


class AidotClient:
    """AiDot client for managing devices and authentication."""

    _device_clients: dict[str, DeviceClient]
    user_info: UserInformation = None
    _token_fresh_cb: Optional[callable] = None
    _products: dict[str, dict[str, Any]] = {}

    def __init__(
        self,
        session: Optional[ClientSession],
        country_code: str | None = None,
        username: str | None = None,
        password: str | None = None,
        token: dict | None = None,
    ) -> None:
        _LOGGER.info("Client Version: v0.3.54b3")
        self.country_code = country_code
        self._device_clients = {}
        self.user_info = UserInformation(
            username=username, password=password, country_code=country_code
        )

        # Set region and country from country_code
        for item in SUPPORTED_COUNTRYS:
            if item[CONF_ID] == self.country_code:
                self.user_info.country = item["name"]
                self.user_info.region = item["region"].lower()
                break

        # Handle token (existing login info)
        if token is not None:
            if token.get(CONF_ID) is None and token.get(CONF_LOGIN_INFO) is not None:
                token = token.get(CONF_LOGIN_INFO)
            self.user_info.update_from_json(token)

        # Setup CloudApi
        CloudApi.set_session(session)
        CloudApi.set_user_info(self.user_info)
        CloudApi.set_auth_failed_callback(self._on_auth_failed)
        CloudApi.set_token_refreshed_callback(self._on_token_refreshed)
        self.setup_discover()

    @property
    def login_info(self) -> dict:
        return self.user_info.to_dict()

    def _on_auth_failed(self) -> None:
        """Handle authentication failed event from CloudApi."""
        _LOGGER.warning("Authentication failed, clearing user info")
        self.user_info.accessToken = ""

    def _on_token_refreshed(self) -> None:
        """Handle token refreshed event from CloudApi."""
        _LOGGER.debug("Token refreshed successfully")
        if self._token_fresh_cb:
            self._token_fresh_cb()

    def set_token_fresh_cb(self, callback) -> None:
        """Set callback for token refresh events."""
        self._token_fresh_cb = callback

    async def get_terminal_id(self) -> str:
        """Get or create terminal ID for device identification."""
        file_path = Path.home() / ".aidot_terminal_id"

        def _read_or_create() -> str:
            try:
                if file_path.exists():
                    return file_path.read_text().strip()
                node = uuid.getnode()
                is_random = (node >> 40) & 1
                raw_id = str(uuid.uuid4()) if is_random else format(node, "x")
                file_path.write_text(raw_id)
                return raw_id
            except OSError:
                return "gvz3gjae10l4zii00t7y0"

        raw_id = await asyncio.to_thread(_read_or_create)
        return hashlib.md5(raw_id.encode()).hexdigest()

    async def async_post_login(self) -> dict[str, Any]:
        """Login the user input allows us to connect."""
        terminal_id = await self.get_terminal_id()

        login_request = LoginRequest.create(
            username=self.user_info.username,
            encrypted_password=rsa_encrypt(self.user_info.password, PUBLIC_KEY_PEM),
            country_name=self.user_info.country,
            terminal_id=terminal_id,
        )

        response_data = await CloudApi.login(login_request.to_dict())
        self.user_info.update_from_json(response_data)
        self.setup_discover()
        return self.user_info.to_dict()

    async def async_get_all_device(self) -> dict[str, Any]:
        """Get all devices for the user."""
        filter_devices: dict[str, Any] = {}
        filter_product_ids: set[str] = set()
        try:
            houses = await CloudApi.get_houses() or []
            for house in houses:
                if house.get(CONF_IS_OWNER) is False:
                    continue
                device_list = await CloudApi.get_devices(house[CONF_ID]) or []
                for device in device_list:
                    filter_device: dict[str, Any] = None
                    if (
                        device.get(CONF_TYPE) == "light"
                        and device.get(CONF_AES_KEY, [None])[0] is not None
                    ):
                        filter_device = device
                    if filter_device is not None:
                        filter_devices[device[CONF_ID]] = device
                        filter_product_ids.add(device[CONF_PRODUCT_ID])

            # Get product info and merge into devices
            if filter_product_ids:
                product_ids = ",".join(filter_product_ids)
                product_list = await CloudApi.get_products(product_ids) or []
                product_map = {p[CONF_ID]: p for p in product_list}
                for device in filter_devices.values():
                    device[CONF_PRODUCT] = product_map.get(device[CONF_PRODUCT_ID])

        except Exception as e:
            raise e
        return filter_devices

    def get_device_client(self, device: dict[str, Any]) -> DeviceClient:
        """Get or create device client for a device."""
        _device: DeviceModel = DeviceModel.from_json(data=device)
        device_client: DeviceClient = self._device_clients.get(_device.id)
        if device_client is None:
            device_client = DeviceClient(_device, self.user_info)
            self._device_clients[_device.id] = device_client

        ip = Discover.DISCOVERED_DEVICE.get(_device.id)
        device_client.update_ip_address(ip)
        return device_client

    async def remove_device_client(self, dev_id: str) -> None:
        """Remove and close device client."""
        device_client: DeviceClient = self._device_clients.get(dev_id)
        if device_client is not None:
            await device_client.close()
            del self._device_clients[dev_id]

    def setup_discover(self) -> None:
        """Initialize device discovery after login."""
        if not self.user_info.id:
            return

        _LOGGER.warning("setup_discover")

        def _discover_callback(dev_id: str, event: dict[str, str]) -> None:
            device_ip = event[CONF_IPADDRESS]
            device_client: DeviceClient = self._device_clients.get(dev_id)
            if device_client is not None:
                device_client.update_ip_address(device_ip)

        Discover.set_call_back(_discover_callback)
        Discover.set_user_info(self.user_info)

    async def async_close(self) -> None:
        """Close client and cleanup resources."""
        for client in self._device_clients.values():
            await client.close()
        self._device_clients.clear()

    async def async_cleanup(self) -> None:
        """Cleanup all resources."""
        _LOGGER.debug("async_cleanup")
        await self.async_close()
