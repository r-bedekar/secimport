"""
Azure Connector -- resource inventory via azure-mgmt-resource.

API Docs: https://learn.microsoft.com/en-us/python/api/azure-mgmt-resource/

Status: STUB -- Community contribution welcome!
"""

import logging
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedAsset, ParsedOwnerMapping
from ..base import AuthConfig, ConnectionConfig, ConnectorStatus
from .base import BaseCloudConnector

logger = logging.getLogger("secimport.connectors.cloud.azure")


class AzureConnector(BaseCloudConnector):
    """
    Azure resource inventory connector using azure-identity and azure-mgmt-resource.

    Authenticates with an Azure service principal via OAuth2 client credentials
    passed in ``AuthConfig(auth_type="oauth2", credentials={...})``.

    Usage::

        from secimport.connectors.cloud import AzureConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://management.azure.com")
        auth = AuthConfig(
            auth_type="oauth2",
            credentials={
                "client_id": "...",
                "client_secret": "...",
                "tenant_id": "...",
                "subscription_id": "...",
            },
        )

        with AzureConnector(config, auth) as azure:
            for asset in azure.get_resources():
                print(asset.hostname, asset.asset_type)
    """

    name: ClassVar[str] = "azure"
    vendor: ClassVar[str] = "Microsoft"
    description: ClassVar[str] = "Azure resource inventory"
    auth_types: ClassVar[Tuple[str, ...]] = ("oauth2",)

    DEFAULT_OWNER_TAG_KEYS: ClassVar[List[str]] = [
        "Owner",
        "Team",
        "Department",
        "CostCenter",
        "BusinessUnit",
    ]

    # -- init ------------------------------------------------------------------

    def __init__(
        self,
        connection: ConnectionConfig,
        auth: AuthConfig,
    ) -> None:
        """Initialise the Azure connector.

        Args:
            connection: Connection configuration
                (``base_url`` defaults to Azure Resource Manager endpoint).
            auth: Auth config with ``credentials`` containing
                ``client_id``, ``client_secret``, ``tenant_id``, and
                ``subscription_id``.
        """
        super().__init__(connection, auth)
        self._credential: Any = None
        self._resource_client: Any = None

    # -- connect / disconnect / test -------------------------------------------

    def connect(self) -> bool:
        """
        Create Azure credential and ResourceManagementClient.

        Returns:
            ``True`` on success; raises ``ConnectionError`` on failure.
        """
        from azure.identity import ClientSecretCredential  # type: ignore[import-untyped]
        from azure.mgmt.resource import ResourceManagementClient  # type: ignore[import-untyped]

        creds = self.auth.credentials
        try:
            self._credential = ClientSecretCredential(
                tenant_id=creds["tenant_id"],
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
            )
            self._resource_client = ResourceManagementClient(
                credential=self._credential,
                subscription_id=creds["subscription_id"],
            )

            if self.test_connection():
                self.status = ConnectorStatus.CONNECTED
                logger.info(
                    "%s: connected to Azure subscription %s",
                    self.name,
                    creds["subscription_id"],
                )
                return True

            self.disconnect()
            return False
        except Exception as exc:
            self.status = ConnectorStatus.ERROR
            self.disconnect()
            raise ConnectionError(
                f"Failed to connect to {self.name}: {exc}"
            ) from exc

    def disconnect(self) -> None:
        """Release Azure SDK clients."""
        if self._credential is not None:
            # ClientSecretCredential supports close() for cleanup.
            close = getattr(self._credential, "close", None)
            if callable(close):
                close()
        self._credential = None
        self._resource_client = None
        self.status = ConnectorStatus.DISCONNECTED

    def test_connection(self) -> bool:
        """Validate credentials by listing resource groups (limit 1)."""
        try:
            rg_pager = self._resource_client.resource_groups.list()  # type: ignore[union-attr]
            # Consume one item to verify credentials work.
            next(iter(rg_pager))
            return True
        except StopIteration:
            # No resource groups but credentials are valid.
            return True
        except Exception:
            return False

    # -- data methods (stubs) --------------------------------------------------

    def get_resources(
        self,
        resource_type: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedAsset]:
        """
        Fetch Azure resources as normalised assets.

        Args:
            resource_type: Azure resource type filter
                (e.g. ``"Microsoft.Compute/virtualMachines"``).
            limit: Maximum number of resources to return.

        Yields:
            ``ParsedAsset`` objects.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_tags(self, resource_id: str) -> Dict[str, str]:
        """
        Retrieve tags for an Azure resource.

        Args:
            resource_id: Full Azure resource ID.

        Returns:
            Dict mapping tag key to tag value.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_owner_from_tags(
        self,
        resource_id: str,
        owner_tag_keys: Optional[List[str]] = None,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Derive owner information from Azure resource tags.

        Args:
            resource_id: Full Azure resource ID.
            owner_tag_keys: Ordered list of tag keys to check.
                Defaults to ``DEFAULT_OWNER_TAG_KEYS``.

        Returns:
            ``ParsedOwnerMapping`` if an owner tag is found, ``None`` otherwise.
        """
        raise NotImplementedError("Community contribution welcome!")

    # -- parse helper ----------------------------------------------------------

    def _parse_resource(self, raw: Dict[str, Any]) -> ParsedAsset:
        """
        Map a raw Azure resource dict to ``ParsedAsset``.

        Args:
            raw: Azure SDK ``GenericResourceExpanded`` serialised as dict.

        Returns:
            Normalised ``ParsedAsset``.
        """
        tags: Dict[str, str] = raw.get("tags") or {}
        return ParsedAsset(
            hostname=raw.get("name"),
            asset_type=raw.get("type"),
            environment=tags.get("Environment"),
            criticality=tags.get("Criticality"),
            owner_email=tags.get("Owner"),
            department=tags.get("Department"),
            business_unit=tags.get("BusinessUnit"),
            cost_center=tags.get("CostCenter"),
            location=raw.get("location"),
            extra={
                "resource_id": raw.get("id"),
                "resource_group": raw.get("resource_group"),
                "kind": raw.get("kind"),
                "sku": raw.get("sku"),
                "provisioning_state": raw.get("provisioning_state"),
                "tags": tags,
            },
        )
