"""Firebase Cloud Messaging receiver for Thermomix cook-state pushes.

Thermomix HA v0.1.1 with locally scoped FCM decoder compatibility fix.
This file replaces only custom_components/thermomix/receiver.py.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import json
import logging
from typing import Any

from aiohttp import ClientSession
from cookidoo_api import Cookidoo, cooking_activity_from_push
from cookidoo_api.types import CookidooCookingActivity
from firebase_messaging import FcmPushClient, FcmRegisterConfig

_LOGGER = logging.getLogger(__name__)

# Public Cookidoo Android application client identifiers.
FCM_PROJECT_ID = "cookidoo-app"
FCM_APP_ID = "1:447648593759:android:ebfbf2b01378844b"
FCM_API_KEY = "AIzaSyCPyZm8EAdpVhWhNLFv3cOw_Kx4iNxR_E4"
FCM_SENDER_ID = "447648593759"

FCM_CHECKIN_ATTEMPTS = 4
FCM_CHECKIN_RETRY_DELAY_S = 2
PUSH_NESTED_PAYLOAD_KEYS = ("cookingActivity", "remoteMonitoringInfo")

PushCallback = Callable[[CookidooCookingActivity, dict[str, Any]], None]


def cook_state_payload(message: Any) -> dict[str, Any] | None:
    """Extract the cook-state mapping from a Firebase data message."""
    if not isinstance(message, dict):
        return None
    data = message.get("data", message)
    if not isinstance(data, dict):
        return None
    if "deviceId" in data:
        return data
    for key in PUSH_NESTED_PAYLOAD_KEYS:
        value = data.get(key)
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                return dict(json.loads(value))
            except (json.JSONDecodeError, TypeError, ValueError):
                _LOGGER.debug("Could not decode the %s push payload", key)
                return None
    return None


def token_from_credentials(credentials: Any) -> str | None:
    """Return the FCM registration token held by a credentials mapping."""
    try:
        token = credentials["fcm"]["registration"]["token"]
    except (KeyError, TypeError):
        return None
    return token if isinstance(token, str) else None


async def _close_register(client: FcmPushClient) -> None:
    """Close the session a rejected check-in leaves behind."""
    register = getattr(client, "register", None)
    if register is not None:
        await register.close()


# NOTE: This subclass changes behavior ONLY for the Thermomix receiver.
# It never modifies firebase_messaging or the behavior of other integrations.
# Inspired by the unmerged upstream fixes:
# https://github.com/sdb9696/firebase-messaging/pull/37
# https://github.com/sdb9696/firebase-messaging/pull/43
class _ThermomixResilientFcmPushClient(FcmPushClient):
    """Decode stripped-padding and multi-parameter FCM Web Push headers.

    Keep listening if a single message is not decryptable. The fix is limited
    to this local subclass, compatible with firebase-messaging 0.4.x.
    """

    @staticmethod
    def _webpush_param(header: str, name: str) -> str:
        """Find dh/salt even when the header contains multiple parameters."""
        for segment in header.split(";"):
            param, sep, value = segment.strip().partition("=")
            if sep and param.strip().lower() == name:
                return value.strip()
        # Bare base64url value: '=' can occur only at the very end as padding.
        bare = header.strip()
        if ";" not in bare and "=" not in bare.rstrip("="):
            return bare
        raise ValueError(f"FCM Web Push header missing {name!r} parameter")

    def _app_data_by_key(self, p: Any, key: str, do_not_raise: bool = False) -> str:
        value = super()._app_data_by_key(p, key, do_not_raise)
        if not value:
            return value
        # firebase-messaging 0.4.x slices off precisely the first 3 or 5
        # characters ('dh=' and 'salt='). Normalize without patching it.
        if key == "crypto-key":
            return "dh=" + self._webpush_param(value, "dh")
        if key == "encryption":
            return "salt=" + self._webpush_param(value, "salt")
        return value

    @staticmethod
    def _decrypt_raw_data(
        credentials: dict[str, dict[str, str]],
        crypto_key_str: str,
        salt_str: str,
        raw_data: bytes,
    ) -> bytes:
        """Restore RFC base64url padding for DH key and salt."""
        def padded(value: str) -> str:
            return value + "=" * (-len(value) % 4)

        return FcmPushClient._decrypt_raw_data(
            credentials, padded(crypto_key_str), padded(salt_str), raw_data
        )

    def _handle_data_message(self, msg: Any) -> None:
        try:
            super()._handle_data_message(msg)
        except (ValueError, TypeError, KeyError, RuntimeError) as exc:
            # Never print raw payload, crypto material, or personal data.
            _LOGGER.warning(
                "Skipping undecodable Thermomix FCM message (%s); "
                "the push receiver remains running",
                type(exc).__name__,
            )


class ThermomixPushReceiver:
    """Receives live cook state for the appliances of a Cookidoo account.

    Reuse persisted FCM credentials so the push token survives restarts.
    """

    def __init__(
        self,
        cookidoo: Cookidoo,
        on_push: PushCallback,
        *,
        mobile_app_id: str,
        session: ClientSession | None = None,
        credentials: dict[str, Any] | None = None,
        on_credentials: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._cookidoo = cookidoo
        self._on_push = on_push
        self._mobile_app_id = mobile_app_id
        self._session = session
        self._credentials = credentials
        self._on_credentials = on_credentials
        self._client: FcmPushClient | None = None
        self._token: str | None = None
        self._registered_token: str | None = None
        self._reregister_task: asyncio.Task[None] | None = None

    @property
    def credentials(self) -> dict[str, Any] | None:
        return self._credentials

    @property
    def token(self) -> str | None:
        return self._token

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_started()

    async def start(self) -> None:
        """Connect to FCM and register the token for cook-state pushes."""
        client = _ThermomixResilientFcmPushClient(
            self._handle_message,
            FcmRegisterConfig(
                project_id=FCM_PROJECT_ID,
                app_id=FCM_APP_ID,
                api_key=FCM_API_KEY,
                messaging_sender_id=FCM_SENDER_ID,
            ),
            self._credentials,
            self._handle_credentials,
            http_client_session=self._session,
        )
        self._token = await self._checkin(client)
        await client.start()
        self._client = client
        await self._register(self._token)

    async def _checkin(self, client: FcmPushClient) -> str:
        for attempt in range(1, FCM_CHECKIN_ATTEMPTS):
            try:
                return await client.checkin_or_register()
            except RuntimeError as exc:
                _LOGGER.debug("Firebase check-in attempt %s failed: %s", attempt, exc)
                await _close_register(client)
                await asyncio.sleep(FCM_CHECKIN_RETRY_DELAY_S)
        return await client.checkin_or_register()

    async def stop(self) -> None:
        if self._reregister_task is not None:
            self._reregister_task.cancel()
            self._reregister_task = None
        if self._registered_token is not None:
            try:
                await self._cookidoo.unregister_push_token(self._registered_token)
            except Exception:
                _LOGGER.debug("Unregistering the push token failed", exc_info=True)
            self._registered_token = None
        if self._client is not None:
            await self._client.stop()
            self._client = None

    async def _register(self, token: str) -> None:
        await self._cookidoo.register_push_token(token, self._mobile_app_id)
        self._registered_token = token

    def _handle_message(
        self, message: dict[str, Any], persistent_id: str, context: Any = None
    ) -> None:
        payload = cook_state_payload(message)
        if payload is None:
            _LOGGER.debug("Ignoring a push without cook state: %s", sorted(message))
            return
        try:
            activity = cooking_activity_from_push(payload)
        except (ValueError, TypeError, KeyError):
            _LOGGER.warning("Could not decode a cook-state push: %s", payload)
            return
        self._on_push(activity, dict(payload))

    def _handle_credentials(self, credentials: dict[str, Any]) -> None:
        self._credentials = credentials
        if self._on_credentials is not None:
            self._on_credentials(credentials)
        token = token_from_credentials(credentials)
        if token is not None and token != self._registered_token:
            self._token = token
            self._reregister_task = asyncio.create_task(self._async_reregister(token))

    async def _async_reregister(self, token: str) -> None:
        try:
            await self._register(token)
        except Exception:
            _LOGGER.warning("Re-registering the rotated Thermomix push token failed")
            _LOGGER.debug("Re-registration traceback", exc_info=True)
