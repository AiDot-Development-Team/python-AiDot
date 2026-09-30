"""Tests for the AiDot device client."""

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from aidot.const import (
    CONF_AES_KEY,
    CONF_ID,
    CONF_MODEL_ID,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_PROPERTIES,
)
from aidot.device_client import DeviceClient


class DeviceClientTest(unittest.TestCase):
    """Test device client helpers."""

    def test_get_valid_ip(self) -> None:
        """Validate IP address strings."""
        self.assertEqual(DeviceClient._get_valid_ip("192.168.1.10"), "192.168.1.10")
        self.assertEqual(DeviceClient._get_valid_ip("2001:db8::1"), "2001:db8::1")
        self.assertIsNone(DeviceClient._get_valid_ip(""))
        self.assertIsNone(DeviceClient._get_valid_ip(None))
        self.assertIsNone(DeviceClient._get_valid_ip("999.168.1.10"))
        self.assertIsNone(DeviceClient._get_valid_ip("not-an-ip"))


class AsyncDeviceClientTest(unittest.IsolatedAsyncioTestCase):
    """Test async device client behavior."""

    def _create_device(self, ip_address: str) -> dict:
        """Create a test device."""
        return {
            CONF_ID: "device-id",
            CONF_NAME: "Test Light",
            CONF_MODEL_ID: "aidot.light.rgbw",
            CONF_AES_KEY: ["mock_aes_key"],
            CONF_PASSWORD: "password",
            CONF_PROPERTIES: {"ipAddress": ip_address},
        }

    async def test_init_with_valid_ip_schedules_login(self) -> None:
        """A valid IP from cloud properties triggers an initial login attempt."""
        with patch.object(DeviceClient, "async_login", new=AsyncMock()) as mock_login:
            device_client = DeviceClient(self._create_device("192.168.1.10"), {}, None)
            await asyncio.sleep(0)

        self.assertEqual(device_client._ip_address, "192.168.1.10")
        mock_login.assert_awaited_once()

    async def test_init_with_invalid_ip_does_not_schedule_login(self) -> None:
        """An invalid IP from cloud properties is ignored."""
        with patch.object(DeviceClient, "async_login", new=AsyncMock()) as mock_login:
            device_client = DeviceClient(self._create_device("not-an-ip"), {}, None)
            await asyncio.sleep(0)

        self.assertIsNone(device_client._ip_address)
        mock_login.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
