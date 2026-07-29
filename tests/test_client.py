"""Tests for the AiDot client."""

import unittest
from typing import Any

import aiohttp

from aidot.client import AidotClient
from aidot.const import (
    CONF_ACCESS_TOKEN,
    CONF_COUNTRY,
    CONF_ID,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_REGION,
    CONF_USERNAME,
)


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


if __name__ == "__main__":
    unittest.main()
