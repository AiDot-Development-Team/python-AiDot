"""The aidot integration."""

import asyncio
import logging
import base64
import random
import aiohttp
from aiohttp import ClientSession
from typing import Any, Optional
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import uuid
from pathlib import Path
import hashlib
from .exceptions import AidotAuthFailed, AidotUserOrPassIncorrect
from .device_client import DeviceClient
from .models.device_model import EffectResp, FavoriteEffectPrimitive
from .discover import Discover
from .login_const import APP_ID, PUBLIC_KEY_PEM, API_URL_TEMPLATE, DEFAULT_REGION
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_APP_ID,
    CONF_CODE,
    CONF_COUNTRY,
    CONF_DEVICE_LIST,
    CONF_DIYS,
    CONF_EFFECTS,
    CONF_EFFECT_SOURCE,
    CONF_FAV_PRESETS,
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
    DEFAULT_COUNTRY_CODE,
    CONF_IS_OWNER,
    CONF_LOGIN_INFO,
    ServerErrorCode,
    CONF_MODEL_ID,
    CONF_PROPERTIES,
    CONF_LIGHT_SCRIPT_FLAGS,
    CONF_PRESETS,
    CONF_TYPE,
    CONF_AES_KEY,
    CONF_FIRMWARE_VERSION,
    CONF_PRIMITIVE,
    DEFAULT_EFFECT_SOURCE,
    EFFECT_SOURCE_RECOMMENDED,
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
    def __init__(
        self,
        session: Optional[ClientSession],
        country_code: str | None = None,
        username: str | None = None,
        password: str | None = None,
        token: dict | None = None,
        options: dict[str, Any] | None = None,
        effect_source: str = DEFAULT_EFFECT_SOURCE,
    ) -> None:
        _LOGGER.info("Client Version: v0.3.57")
        self.session = session
        self.options = options.copy() if options is not None else {}
        self.effect_source = self.options.get(CONF_EFFECT_SOURCE, effect_source)
        self.username = username
        self.password = password
        self.country_code = country_code or DEFAULT_COUNTRY_CODE
        self.country_name = DEFAULT_COUNTRY_NAME
        self._region = DEFAULT_REGION
        self._base_url = API_URL_TEMPLATE.format(region=self._region)
        self.login_info: dict[str, Any] = {}
        self._device_clients = {}
        self._effect_mode_params_cache: dict[
            tuple[str, str, str, bool], dict[str, Any]
        ] = {}
        self._discover: Discover | None = None
        self._token_fresh_cb = None
        for item in SUPPORTED_COUNTRYS:
            if item["id"] == self.country_code:
                self.country_name = item["name"]
                self._region = item["region"].lower()
                self._base_url = API_URL_TEMPLATE.format(region=self._region)
                break
        if token is not None:
            # ✅ 兼容性处理: v1.0.8 数据结构迁移到 v1.1.3
            # 旧版本: config_entry.data[CONF_LOGIN_INFO]
            # 新版本: config_entry.data
            if token.get(CONF_ID) is None and token.get(CONF_LOGIN_INFO) is not None:
                token = token.get(CONF_LOGIN_INFO)

            self.login_info = token.copy()
            self.username = token[CONF_USERNAME]
            self.password = token[CONF_PASSWORD]
            self._region = token[CONF_REGION]
            self.country_name = token[CONF_COUNTRY]
            self._base_url = API_URL_TEMPLATE.format(region=self._region)
        self.setup_discover()

    def set_token_fresh_cb(self, callback) -> None:
        self._token_fresh_cb = callback

    def get_identifier(self) -> str:
        return f"{self._region}-{self.username}"

    def update_password(self, password: str) -> None:
        self.password = password

    async def get_terminal_id(self) -> str:
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
        url = f"{self._base_url}/users/loginWithFreeVerification"
        headers = {CONF_APP_ID: APP_ID, CONF_TERMINAL: "app"}
        # f"{region}:{self.country_name.strip()}",
        terminalId = await self.get_terminal_id()
        if terminalId is None:
            terminalId = "gvz3gjae10l4zii00t7y0"
        data = {
            "countryKey": f"region:{self.country_name.strip()}",
            "username": self.username,
            "password": rsa_password_encrypt(self.password),
            "terminalId": terminalId,
            "webVersion": "0.5.0",
            "area": "Asia/Shanghai",
            "UTC": "UTC+8",
        }

        response_data: dict[str, Any] = {}
        try:
            response = await self.session.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()
            self.login_info = response_data
            self.login_info[CONF_PASSWORD] = self.password
            self.login_info[CONF_REGION] = self._region
            self.login_info[CONF_COUNTRY] = self.country_name
            self.setup_discover()
            return self.login_info
        except aiohttp.ClientError as err:
            _LOGGER.error("async_post_login ClientError: %s", err)
            if response_data.get(CONF_CODE) == ServerErrorCode.USER_PWD_INCORRECT:
                raise AidotUserOrPassIncorrect from err
            raise

    async def async_refresh_token(self) -> dict[str, Any]:
        url = f"{self._base_url}/users/refreshToken"
        headers = {CONF_APP_ID: APP_ID, CONF_TERMINAL: "app"}
        data = {
            CONF_REFRESH_TOKEN: self.login_info[CONF_REFRESH_TOKEN],
        }

        response_data: dict[str, Any] = {}
        try:
            response = await self.session.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()
            self.login_info[CONF_ACCESS_TOKEN] = response_data[CONF_ACCESS_TOKEN]
            if response_data[CONF_REFRESH_TOKEN] is not None:
                self.login_info[CONF_REFRESH_TOKEN] = response_data[CONF_REFRESH_TOKEN]
            _LOGGER.debug(f"refresh token: {response_data}")
            if self._token_fresh_cb:
                self._token_fresh_cb()
            return response_data
        except aiohttp.ClientError as err:
            _LOGGER.error("async_refresh_token ClientError: %s %s", err, response_data)
            if response_data.get(CONF_CODE) == ServerErrorCode.LOGIN_INVALID:
                raise AidotAuthFailed from err
            raise

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
        except aiohttp.ClientError as err:
            _LOGGER.error("async_get ClientError: %s %s", err, response_data)
            code = response_data.get(CONF_CODE)
            if code == ServerErrorCode.TOKEN_EXPIRED:
                try:
                    await self.async_refresh_token()
                    return await self.async_session_get(params)
                except AidotAuthFailed as auth_err:
                    raise AidotAuthFailed from auth_err
            elif (
                code == ServerErrorCode.LOGIN_INVALID or code == 21027 or code == 21041
            ):
                self.login_info[CONF_ACCESS_TOKEN] = None
                raise AidotAuthFailed from err
            raise

    async def async_session_post(
        self,
        params: str,
        data: Any,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Post data to AiDot API."""
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
            response = await self.session.post(url, headers=headers, json=data)
            response_data = await response.json()
            response.raise_for_status()
            return response_data
        except aiohttp.ClientError as err:
            _LOGGER.error("async_post ClientError: %s %s", err, response_data)
            code = response_data.get(CONF_CODE)
            if code == ServerErrorCode.TOKEN_EXPIRED:
                try:
                    await self.async_refresh_token()
                    return await self.async_session_post(params, data)
                except AidotAuthFailed as auth_err:
                    raise AidotAuthFailed from auth_err
            elif (
                code == ServerErrorCode.LOGIN_INVALID or code == 21027 or code == 21041
            ):
                self.login_info[CONF_ACCESS_TOKEN] = None
                raise AidotAuthFailed from err
            raise

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

    async def async_get_diy_list(
        self, device: dict[str, Any]
    ) -> list[FavoriteEffectPrimitive]:
        """Get favorite list."""
        params = f"/devices/{device[CONF_ID]}/v4.0/favoriteEffectMode"
        resp = await self.async_session_get(params)
        return EffectResp.from_json(resp).primitive

    async def async_get_fav_presets(
        self, device: dict[str, Any]
    ) -> list[FavoriteEffectPrimitive]:
        """Get favorite list."""
        # https://prod-us-api.arnoo.com/v35/devices/8a040e2233a243e7a07eb6a1b7a210a7/v4.0/favoriteEffectMode?libraryId=aidot.preset

        params = (
            f"/devices/{device[CONF_ID]}/v4.0/favoriteEffectMode?libraryId=aidot.preset"
        )
        resp = await self.async_session_get(params)
        return EffectResp.from_json(resp).primitive

    async def async_get_presets(
        self, device: dict[str, Any]
    ) -> list[FavoriteEffectPrimitive]:
        """Get preset list."""
        # https://prod-us-api.arnoo.com/v35/models/LK.light.A001855/v3.0/effectModes?libraryId=aidot.preset&version=3.30.09&lightScriptFlags=0002140503140500000062

        params = (
            f"/models/{device[CONF_MODEL_ID]}/v3.0/effectModes?libraryId=aidot.preset"
        )
        properties = device.get(CONF_PROPERTIES, {})
        light_script_flags = properties.get(CONF_LIGHT_SCRIPT_FLAGS)
        if light_script_flags:
            params = (
                f"{params}&version={device[CONF_FIRMWARE_VERSION]}"
                f"&lightScriptFlags={light_script_flags}"
            )
        resp = await self.async_session_get(params)
        return EffectResp.from_json(resp).primitive

    async def async_get_effect_mode_params(
        self,
        device_id: str,
        primitive: FavoriteEffectPrimitive,
    ) -> dict[str, Any]:
        """Get effect mode params."""
        primitive_effect_id = primitive.primitiveEffectId
        favorite_id = primitive.favoriteId
        library_id = primitive.libraryId
        if favorite_id is not None:
            effect_query = f"favoriteIds={favorite_id}"
            effect_cache_id = favorite_id
        elif primitive_effect_id is not None:
            effect_query = f"primitiveEffectIds={primitive_effect_id}"
            effect_cache_id = primitive_effect_id
        else:
            raise ValueError(
                "Effect primitive must have favoriteId or primitiveEffectId"
            )
        if library_id is None:
            raise ValueError("Effect primitive must have libraryId")

        cache_key = (device_id, effect_cache_id, library_id, primitive.isOldParams)
        if cache_key in self._effect_mode_params_cache:
            return self._effect_mode_params_cache[cache_key]

        params = (
            f"/devices/{device_id}/v3.0/effectModeParams"
            f"?{effect_query}"
            f"&isOldParams={primitive.isOldParams}"
            f"&libraryId={library_id}"
        )
        resp = await self.async_session_get(params)
        effect_primitives = resp.get(CONF_PRIMITIVE) or []
        if not effect_primitives:
            raise ValueError("Effect mode params response has no primitive")

        effect_params = effect_primitives[0]
        self._effect_mode_params_cache[cache_key] = effect_params
        return effect_params

    async def async_execute_diff_command(
        self,
        device_id: str,
        primitive: FavoriteEffectPrimitive,
    ) -> dict[str, Any]:
        """Execute diff command."""
        # effect_params = await self.async_get_effect_mode_params(device_id, primitive)
        data = [
            {
                "devId": device_id,
                "effectUniqueID": primitive.primitiveEffectId,
                "action": "runLScript",
                "in": [
                    {
                        "sessionId": random.randint(1, 2_147_483_647),
                        # "params": effect_params["params"],
                    }
                ],
            }
        ]
        return await self.async_session_post("/devices/execute/diffCommand", data)

    async def async_get_all_effects(
        self, device: dict[str, Any]
    ) -> dict[str, FavoriteEffectPrimitive]:
        """Get all effects list and store raw effect sources on the device."""
        diy_list: list[FavoriteEffectPrimitive] = []
        fav_preset: list[FavoriteEffectPrimitive] = []
        preset_list: list[FavoriteEffectPrimitive] = []

        try:
            diy_list = await self.async_get_diy_list(device)
        except Exception as err:
            _LOGGER.warning(
                "Failed to get DIY effects for %s: %s", device[CONF_ID], err
            )

        try:
            fav_preset = await self.async_get_fav_presets(device)
        except Exception as err:
            _LOGGER.warning(
                "Failed to get favorite preset effects for %s: %s",
                device[CONF_ID],
                err,
            )

        try:
            preset_list = await self.async_get_presets(device)
        except Exception as err:
            _LOGGER.warning(
                "Failed to get preset effects for %s: %s", device[CONF_ID], err
            )

        fav_preset_ids = {
            item.primitiveEffectId
            for item in fav_preset
            if item.primitiveEffectId is not None
        }
        preset_list = [
            item for item in preset_list if item.primitiveEffectId not in fav_preset_ids
        ]

        device[CONF_DIYS] = diy_list
        device[CONF_FAV_PRESETS] = fav_preset
        device[CONF_PRESETS] = preset_list
        return self.get_filtered_effects(device)

    def get_filtered_effects(
        self, device: dict[str, Any]
    ) -> dict[str, FavoriteEffectPrimitive]:
        """Get final effects for Home Assistant from raw device effect sources."""
        diy_list = device.get(CONF_DIYS, [])
        fav_preset = device.get(CONF_FAV_PRESETS, [])
        preset_list = device.get(CONF_PRESETS, [])

        return self._merge_effects_by_unique_name(
            diy_list,
            fav_preset,
            self._filter_preset_list(preset_list),
        )

    def _filter_preset_list(
        self, preset_list: list[FavoriteEffectPrimitive]
    ) -> list[FavoriteEffectPrimitive]:
        """Filter preset effects by configured source."""
        if self.effect_source != EFFECT_SOURCE_RECOMMENDED:
            return preset_list

        recommended = [
            effect for effect in preset_list if self._is_recommended_effect(effect)
        ]
        if recommended:
            return recommended
        return preset_list[:10]

    @staticmethod
    def _is_recommended_effect(effect: FavoriteEffectPrimitive) -> bool:
        """Return whether an effect should be included in recommended presets."""
        return effect.tag not in (None, "") and effect.tag.strip() != "New"

    @staticmethod
    def _merge_effects_by_unique_name(
        *effect_lists: list[FavoriteEffectPrimitive],
    ) -> dict[str, FavoriteEffectPrimitive]:
        """Merge effect lists into a dict with unique display names."""
        effects: dict[str, FavoriteEffectPrimitive] = {}
        name_counts: dict[str, int] = {}

        for effect_list in effect_lists:
            for effect in effect_list:
                name = (
                    effect.name
                    or effect.primitiveEffectId
                    or effect.favoriteId
                    or "Effect"
                )
                name_counts[name] = name_counts.get(name, 0) + 1
                unique_name = (
                    name if name_counts[name] == 1 else f"{name} ({name_counts[name]})"
                )
                effects[unique_name] = effect

        return effects

    async def async_get_all_device(self) -> dict[str, Any]:
        final_device_list: list[dict[str, Any]] = []
        try:
            houses = await self.async_get_houses()
            for house in houses:
                if house.get(CONF_IS_OWNER) is False:
                    continue
                # get device_list
                device_list = await self.async_get_devices(house[CONF_ID])
                if device_list:
                    final_device_list.extend(device_list)

            # get product_list
            if not final_device_list:
                return {CONF_DEVICE_LIST: []}
            productIds = ",".join([item[CONF_PRODUCT_ID] for item in final_device_list])
            product_list = await self.async_get_products(productIds)

            for product in product_list:
                for device in final_device_list:
                    if device[CONF_PRODUCT_ID] == product[CONF_ID]:
                        device[CONF_PRODUCT] = product

            for device in final_device_list:
                if (
                    device[CONF_TYPE] == "light"
                    and CONF_AES_KEY in device
                    and device[CONF_AES_KEY][0] is not None
                ):
                    device[CONF_EFFECTS] = await self.async_get_all_effects(device)

        except Exception as e:
            raise e
        return {CONF_DEVICE_LIST: final_device_list}

    def get_device_client(self, device: dict[str, Any]) -> DeviceClient:
        device_id = device.get(CONF_ID)
        device_client: DeviceClient = self._device_clients.get(device_id)
        if device_client is None:
            device_client = DeviceClient(device, self.login_info, self)
            self._device_clients[device_id] = device_client
        if self._discover is not None:
            ip = self._discover.discovered_device.get(device_id)
            device_client.update_ip_address(ip)
        return device_client

    async def remove_device_client(self, dev_id: str) -> None:
        device_client: DeviceClient = self._device_clients.get(dev_id)
        if device_client is not None:
            await device_client.close()
            del self._device_clients[dev_id]

    def setup_discover(self) -> None:
        """初始化完成后调用，启动设备发现"""
        if self.login_info.get(CONF_ID) is None:
            return
        if self._discover is not None:
            return

        _LOGGER.warning("setup_discover")

        def _discover_callback(dev_id, event: dict[str, str]) -> None:
            device_ip = event[CONF_IPADDRESS]
            device_client: DeviceClient = self._device_clients.get(dev_id)
            if device_client is not None:
                device_client.update_ip_address(device_ip)

        self._discover = Discover(self.login_info, _discover_callback)
        self._discover.start_repeat_broadcast()

    async def async_close(self) -> None:
        """关闭客户端，清理资源"""
        if self._discover is not None:
            self._discover.close()
            self._discover = None
        for client in self._device_clients.values():
            await client.close()
        self._device_clients.clear()

    async def async_cleanup(self) -> None:
        """清理所有资源"""
        _LOGGER.debug("async_cleanup")
        await self.async_close()
