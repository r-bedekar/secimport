"""
Microsoft Entra ID (Azure AD) Connector via Microsoft Graph API.

API Docs: https://learn.microsoft.com/en-us/graph/api/overview

Status: STUB - Community contribution welcome!
"""

import logging
from typing import Any, ClassVar, Dict, Iterator, Optional, Tuple

import httpx

from ...models.base import ParsedAsset
from .base import BaseDirectoryConnector

logger = logging.getLogger("secimport.connectors")


class AzureADConnector(BaseDirectoryConnector):
    """
    Microsoft Entra ID (Azure AD) connector via the Microsoft Graph API.

    Uses OAuth2 client-credentials flow to obtain an access token from
    the Microsoft identity platform, then queries the Graph API for
    users, groups, and devices.

    Usage::

        from secimport.connectors.directory import AzureADConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://graph.microsoft.com")
        auth = AuthConfig(
            auth_type="oauth2",
            credentials={
                "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "client_secret": "your-client-secret",
                "tenant_id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
            },
        )

        with AzureADConnector(config, auth) as aad:
            for user in aad.get_users(limit=50):
                print(user["displayName"])
    """

    name: ClassVar[str] = "azure_ad"
    vendor: ClassVar[str] = "Microsoft"
    description: ClassVar[str] = "Microsoft Entra ID (Azure AD) via Graph API"
    auth_types: ClassVar[Tuple[str, ...]] = ("oauth2",)

    _test_endpoint: ClassVar[str] = "/v1.0/organization"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "users": "/v1.0/users",
        "groups": "/v1.0/groups",
        "devices": "/v1.0/devices",
        "token": (
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ),
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._access_token: Optional[str] = None

    # -- connect / disconnect (OAuth2 token exchange) --------------------------

    def connect(self) -> bool:
        """
        Establish connection via OAuth2 client-credentials flow.

        Exchanges ``client_id`` / ``client_secret`` / ``tenant_id``
        for a bearer token at the Microsoft identity platform token
        endpoint, then builds an authenticated ``httpx.Client``.
        """
        tenant_id = self.auth.credentials["tenant_id"]
        token_url = self.ENDPOINTS["token"].format(tenant_id=tenant_id)

        token_client = httpx.Client(
            timeout=self.connection.timeout,
            verify=self.connection.verify_ssl,
        )
        try:
            token_response = token_client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.auth.credentials["client_id"],
                    "client_secret": self.auth.credentials["client_secret"],
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            if token_response.status_code != 200:
                raise ConnectionError(
                    "Failed to obtain OAuth2 token from Microsoft identity platform"
                )
            self._access_token = token_response.json()["access_token"]
        finally:
            token_client.close()

        # Build the authenticated Graph API client
        client = self._build_client(
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json",
            },
        )
        return self._connect_with_test(client)

    def disconnect(self) -> None:
        """Close the Graph API client and discard the access token."""
        super().disconnect()
        self._access_token = None

    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Return Microsoft Graph throttling guidance."""
        return {
            "note": "Microsoft Graph uses per-app, per-tenant throttling",
            "see": "https://learn.microsoft.com/en-us/graph/throttling",
        }

    # -- data methods (stubs) --------------------------------------------------

    def get_users(
        self,
        limit: Optional[int] = None,
        search_filter: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        List users from Microsoft Entra ID.

        GET /v1.0/users
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_groups(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        List groups from Microsoft Entra ID.

        GET /v1.0/groups
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_computers(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedAsset]:
        """
        List devices from Microsoft Entra ID.

        GET /v1.0/devices
        """
        raise NotImplementedError("Community contribution welcome!")

    def search(
        self,
        query: str,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Search Microsoft Entra ID using OData ``$filter`` or ``$search``.

        Args:
            query: OData filter expression, e.g.
                ``"displayName eq 'Jane Doe'"``.
            limit: Maximum results to return.
        """
        raise NotImplementedError("Community contribution welcome!")

    # -- parse helper ----------------------------------------------------------

    def _parse_computer(self, raw: Dict[str, Any]) -> ParsedAsset:
        """
        Map a Microsoft Graph device object to ``ParsedAsset``.

        Expected Graph fields::

            id, displayName, operatingSystem, operatingSystemVersion,
            deviceId, accountEnabled, approximateLastSignInDateTime,
            managementType, manufacturer, model
        """
        return ParsedAsset(
            hostname=raw.get("displayName"),
            operating_system=raw.get("operatingSystem"),
            os_version=raw.get("operatingSystemVersion"),
            asset_type="Device",
            extra={
                "azure_device_id": raw.get("deviceId"),
                "entra_object_id": raw.get("id"),
                "account_enabled": raw.get("accountEnabled"),
                "last_sign_in": raw.get("approximateLastSignInDateTime"),
                "management_type": raw.get("managementType"),
                "manufacturer": raw.get("manufacturer"),
                "model": raw.get("model"),
                "source": "azure_ad",
            },
        )
