"""Tests for the AiDot client."""

import unittest
from typing import Any
from unittest.mock import AsyncMock

import aiohttp

from aidot.client import AidotClient
from aidot.const import (
    CONF_ACCESS_TOKEN,
    CONF_COUNTRY,
    CONF_DIYS,
    CONF_EFFECTS,
    CONF_EFFECT_SOURCE,
    CONF_FAV_PRESETS,
    CONF_ID,
    CONF_PASSWORD,
    CONF_PRESETS,
    CONF_REFRESH_TOKEN,
    CONF_REGION,
    CONF_USERNAME,
    EFFECT_SOURCE_RECOMMENDED,
)
from aidot.models.device_model import FavoriteEffectPrimitive


class FakeResponse:
    """Minimal aiohttp response test double."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    async def json(self) -> dict[str, Any]:
        """Return the response payload."""
        return self._data

    def raise_for_status(self) -> None:
        """Represent a successful response."""


class FakeSession:
    """Record requests made by one client."""

    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self.post_calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    async def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any],
    ) -> FakeResponse:
        """Record a POST request."""
        self.post_calls.append((url, headers, json))
        return FakeResponse(self._response)


class FailingSession:
    """Raise a typed connection error for every request."""

    async def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any],
    ) -> FakeResponse:
        """Simulate a network failure."""
        raise aiohttp.ClientConnectionError


def create_token(
    *, username: str, region: str, access_token: str, refresh_token: str
) -> dict[str, Any]:
    """Create stored login data for a client."""
    return {
        CONF_ID: None,
        CONF_USERNAME: username,
        CONF_PASSWORD: "password",
        CONF_COUNTRY: "United States",
        CONF_REGION: region,
        CONF_ACCESS_TOKEN: access_token,
        CONF_REFRESH_TOKEN: refresh_token,
    }


class AidotClientTest(unittest.IsolatedAsyncioTestCase):
    """Verify client state is isolated by account."""

    async def test_multiple_accounts_keep_state_isolated(self) -> None:
        """Refreshing one account does not update another account."""
        first_session = FakeSession(
            {
                CONF_ACCESS_TOKEN: "first-new-access",
                CONF_REFRESH_TOKEN: "first-new-refresh",
            }
        )
        second_session = FakeSession(
            {
                CONF_ACCESS_TOKEN: "second-new-access",
                CONF_REFRESH_TOKEN: "second-new-refresh",
            }
        )
        first_client = AidotClient(
            session=first_session,
            token=create_token(
                username="first@example.com",
                region="us",
                access_token="first-access",
                refresh_token="first-refresh",
            ),
        )
        second_client = AidotClient(
            session=second_session,
            token=create_token(
                username="second@example.com",
                region="eu",
                access_token="second-access",
                refresh_token="second-refresh",
            ),
        )
        refreshed: list[str] = []
        first_client.set_token_fresh_cb(lambda: refreshed.append("first"))
        second_client.set_token_fresh_cb(lambda: refreshed.append("second"))

        await first_client.async_refresh_token()

        self.assertIsNot(first_client.login_info, second_client.login_info)
        self.assertEqual(first_client.login_info[CONF_ACCESS_TOKEN], "first-new-access")
        self.assertEqual(
            first_client.login_info[CONF_REFRESH_TOKEN], "first-new-refresh"
        )
        self.assertEqual(second_client.login_info[CONF_ACCESS_TOKEN], "second-access")
        self.assertEqual(second_client.login_info[CONF_REFRESH_TOKEN], "second-refresh")
        self.assertEqual(second_session.post_calls, [])
        self.assertEqual(refreshed, ["first"])

    async def test_login_preserves_connection_error(self) -> None:
        """Login keeps aiohttp connection errors typed for callers."""
        client = AidotClient(
            session=FailingSession(),
            country_code="US",
            username="user@example.com",
            password="password",
        )

        with self.assertRaises(aiohttp.ClientConnectionError):
            await client.async_post_login()

    def test_recommended_effect_source_keeps_tagged_presets(self) -> None:
        """Recommended effect source keeps tagged presets except New."""
        client = AidotClient(session=None, effect_source=EFFECT_SOURCE_RECOMMENDED)
        presets = [
            FavoriteEffectPrimitive(name="Calm", primitiveEffectId="p_1"),
            FavoriteEffectPrimitive(
                name="Spark",
                primitiveEffectId="p_3",
                tag=" New ",
            ),
            FavoriteEffectPrimitive(
                name="Wave",
                primitiveEffectId="p_4",
                tag="Hot",
            ),
            FavoriteEffectPrimitive(
                name="Blank tag",
                primitiveEffectId="p_5",
                tag="",
            ),
            FavoriteEffectPrimitive(
                name="Space tag",
                primitiveEffectId="p_6",
                tag=" ",
            ),
        ]

        filtered = client._filter_preset_list(presets)

        self.assertEqual(
            [effect.name for effect in filtered],
            ["Wave", "Space tag"],
        )

    def test_options_effect_source_takes_precedence(self) -> None:
        """Options effect source takes precedence over legacy argument."""
        client = AidotClient(
            session=None,
            options={CONF_EFFECT_SOURCE: EFFECT_SOURCE_RECOMMENDED},
        )

        self.assertEqual(client.effect_source, EFFECT_SOURCE_RECOMMENDED)

    def test_recommended_effect_source_falls_back_to_top_ten(self) -> None:
        """Recommended effect source falls back to the first ten presets."""
        client = AidotClient(session=None, effect_source=EFFECT_SOURCE_RECOMMENDED)
        presets = [
            FavoriteEffectPrimitive(
                name=f"Effect {index}", primitiveEffectId=f"p_{index}"
            )
            for index in range(12)
        ]

        filtered = client._filter_preset_list(presets)

        self.assertEqual(len(filtered), 10)
        self.assertEqual(filtered[-1].name, "Effect 9")

    def test_all_effect_source_keeps_all_presets(self) -> None:
        """All effect source keeps all preset effects."""
        client = AidotClient(session=None)
        device = {
            CONF_DIYS: [
                FavoriteEffectPrimitive(name="DIY", primitiveEffectId="d_1")
            ],
            CONF_FAV_PRESETS: [
                FavoriteEffectPrimitive(name="Favorite", primitiveEffectId="f_1")
            ],
            CONF_PRESETS: [
                FavoriteEffectPrimitive(name="Hot", primitiveEffectId="p_1", tag=" "),
                FavoriteEffectPrimitive(
                    name="New", primitiveEffectId="p_2", tag="New"
                ),
                FavoriteEffectPrimitive(name="Plain", primitiveEffectId="p_3"),
            ],
        }

        effects = client.get_filtered_effects(device)

        self.assertEqual(list(effects), ["DIY", "Favorite", "Hot", "New", "Plain"])

    async def test_get_all_effects_stores_raw_lists_before_filtering(self) -> None:
        """All effect sources are stored on the device before final filtering."""
        client = AidotClient(session=None, effect_source=EFFECT_SOURCE_RECOMMENDED)
        diy = [FavoriteEffectPrimitive(name="DIY", primitiveEffectId="d_1")]
        favorite = [
            FavoriteEffectPrimitive(name="Favorite", primitiveEffectId="p_1")
        ]
        presets = [
            FavoriteEffectPrimitive(
                name=f"Preset {index}", primitiveEffectId=f"p_{index}"
            )
            for index in range(12)
        ]
        device = {CONF_ID: "device_id"}
        client.async_get_diy_list = AsyncMock(return_value=diy)
        client.async_get_fav_presets = AsyncMock(return_value=favorite)
        client.async_get_presets = AsyncMock(return_value=presets)

        effects = await client.async_get_all_effects(device)

        self.assertIs(device[CONF_DIYS], diy)
        self.assertIs(device[CONF_FAV_PRESETS], favorite)
        self.assertEqual(
            [effect.primitiveEffectId for effect in device[CONF_PRESETS]],
            ["p_0", *[f"p_{index}" for index in range(2, 12)]],
        )
        self.assertEqual(
            list(effects),
            [
                "DIY",
                "Favorite",
                "Preset 0",
                "Preset 2",
                "Preset 3",
                "Preset 4",
                "Preset 5",
                "Preset 6",
                "Preset 7",
                "Preset 8",
                "Preset 9",
                "Preset 10",
            ],
        )

    def test_device_information_reads_final_effects(self) -> None:
        """Device information uses final effects instead of raw preset list."""
        from aidot.device_client import DeviceInformation

        device = {
            CONF_ID: "device_id",
            "mac": "00:11:22:33:44:55",
            "modelId": "model",
            "name": "Light",
            "hardwareVersion": "1",
            CONF_PRESETS: [
                FavoriteEffectPrimitive(name="Raw", primitiveEffectId="p_raw")
            ],
            CONF_EFFECTS: {
                "Final": FavoriteEffectPrimitive(
                    name="Final", primitiveEffectId="p_final"
                )
            },
        }

        info = DeviceInformation(device)

        self.assertEqual(info.preset_names, ["Final"])


if __name__ == "__main__":
    unittest.main()
