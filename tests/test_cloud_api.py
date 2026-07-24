"""Tests for account-scoped cloud API state."""

import unittest
from typing import Any

from aidot.api.cloud_api import CloudApi
from aidot.const import API_URL_TEMPLATE, APP_ID
from aidot.models.auth_model import UserInformation


class FakeResponse:
    """Minimal aiohttp response test double."""

    status = 200

    def __init__(self, data: Any) -> None:
        self._data = data

    async def json(self) -> Any:
        """Return the configured response data."""
        return self._data

    def raise_for_status(self) -> None:
        """Represent a successful response."""


class FakeSession:
    """Record requests made by one CloudApi instance."""

    def __init__(self, *, refresh_response: dict[str, Any]) -> None:
        self.refresh_response = refresh_response
        self.get_calls: list[tuple[str, dict[str, str]]] = []
        self.post_calls: list[
            tuple[str, dict[str, str], dict[str, Any]]
        ] = []

    async def get(
        self, url: str, *, headers: dict[str, str]
    ) -> FakeResponse:
        """Record a GET request."""
        self.get_calls.append((url, headers))
        return FakeResponse([])

    async def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any],
    ) -> FakeResponse:
        """Record a POST request."""
        self.post_calls.append((url, headers, json))
        return FakeResponse(self.refresh_response)


class CloudApiTest(unittest.IsolatedAsyncioTestCase):
    """Verify separate accounts cannot overwrite each other's state."""

    async def test_multiple_accounts_keep_state_isolated(self) -> None:
        """Each API instance uses its own session, tokens, and callback."""
        first_session = FakeSession(
            refresh_response={
                "accessToken": "first-new-access",
                "refreshToken": "first-new-refresh",
            }
        )
        second_session = FakeSession(
            refresh_response={
                "accessToken": "second-new-access",
                "refreshToken": "second-new-refresh",
            }
        )
        first_user = UserInformation(
            accessToken="first-access",
            refreshToken="first-refresh",
            region="us",
        )
        second_user = UserInformation(
            accessToken="second-access",
            refreshToken="second-refresh",
            region="eu",
        )
        refreshed: list[str] = []

        first_api = CloudApi(
            session=first_session,
            user_info=first_user,
            token_refreshed_callback=lambda: refreshed.append("first"),
        )
        second_api = CloudApi(
            session=second_session,
            user_info=second_user,
            token_refreshed_callback=lambda: refreshed.append("second"),
        )

        await first_api.get_houses()
        await second_api.get_houses()
        await first_api.refresh_token()

        self.assertEqual(
            first_session.get_calls[0],
            (
                f"{API_URL_TEMPLATE.format(region='us')}/houses",
                {
                    "appId": APP_ID,
                    "terminal": "app",
                    "token": "first-access",
                },
            ),
        )
        self.assertEqual(
            second_session.get_calls[0],
            (
                f"{API_URL_TEMPLATE.format(region='eu')}/houses",
                {
                    "appId": APP_ID,
                    "terminal": "app",
                    "token": "second-access",
                },
            ),
        )
        self.assertEqual(
            first_session.post_calls[0],
            (
                f"{API_URL_TEMPLATE.format(region='us')}/users/refreshToken",
                {
                    "appId": APP_ID,
                    "terminal": "app",
                    "token": "first-access",
                },
                {"refreshToken": "first-refresh"},
            ),
        )
        self.assertEqual(second_session.post_calls, [])
        self.assertEqual(first_user.accessToken, "first-new-access")
        self.assertEqual(first_user.refreshToken, "first-new-refresh")
        self.assertEqual(second_user.accessToken, "second-access")
        self.assertEqual(second_user.refreshToken, "second-refresh")
        self.assertEqual(refreshed, ["first"])


if __name__ == "__main__":
    unittest.main()
