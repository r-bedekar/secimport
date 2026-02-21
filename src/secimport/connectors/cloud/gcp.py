"""
GCP Connector -- resource inventory via Cloud Asset API.

API Docs: https://cloud.google.com/asset-inventory/docs/reference/rest

Status: STUB -- Community contribution welcome!
"""

import logging
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedAsset, ParsedOwnerMapping
from ..base import AuthConfig, ConnectionConfig, ConnectorStatus
from .base import BaseCloudConnector

logger = logging.getLogger("secimport.connectors.cloud.gcp")


class GCPConnector(BaseCloudConnector):
    """
    GCP resource inventory connector using the Cloud Asset API.

    Authenticates with a service-account JSON key file whose path is
    provided via ``AuthConfig(auth_type="token", credentials={...})``.

    Usage::

        from secimport.connectors.cloud import GCPConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://cloudasset.googleapis.com")
        auth = AuthConfig(
            auth_type="token",
            credentials={
                "project_id": "my-project-123",
                "service_account_json": "/path/to/service-account.json",
            },
        )

        with GCPConnector(config, auth) as gcp:
            for asset in gcp.get_resources():
                print(asset.hostname, asset.asset_type)
    """

    name: ClassVar[str] = "gcp"
    vendor: ClassVar[str] = "Google Cloud"
    description: ClassVar[str] = "GCP resource inventory via Cloud Asset API"
    auth_types: ClassVar[Tuple[str, ...]] = ("token",)

    DEFAULT_OWNER_TAG_KEYS: ClassVar[List[str]] = [
        "owner",
        "team",
        "department",
        "cost-center",
        "business-unit",
    ]

    # -- init ------------------------------------------------------------------

    def __init__(
        self,
        connection: ConnectionConfig,
        auth: AuthConfig,
    ) -> None:
        """Initialise the GCP connector.

        Args:
            connection: Connection configuration
                (``base_url`` is unused by the SDK client).
            auth: Auth config with ``credentials`` containing
                ``project_id`` and ``service_account_json``
                (path to the service-account key file).
        """
        super().__init__(connection, auth)
        self._asset_client: Any = None

    # -- connect / disconnect / test -------------------------------------------

    def connect(self) -> bool:
        """
        Create the Cloud Asset ``AssetServiceClient``.

        Returns:
            ``True`` on success; raises ``ConnectionError`` on failure.
        """
        from google.cloud import asset_v1  # type: ignore[import-untyped]
        from google.oauth2 import service_account  # type: ignore[import-untyped]

        creds = self.auth.credentials
        try:
            credentials = service_account.Credentials.from_service_account_file(
                creds["service_account_json"],
            )
            self._asset_client = asset_v1.AssetServiceClient(
                credentials=credentials,
            )

            if self.test_connection():
                self.status = ConnectorStatus.CONNECTED
                logger.info(
                    "%s: connected to GCP project %s",
                    self.name,
                    creds["project_id"],
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
        """Release GCP SDK client."""
        if self._asset_client is not None:
            transport = getattr(self._asset_client, "transport", None)
            if transport is not None:
                close = getattr(transport, "close", None)
                if callable(close):
                    close()
        self._asset_client = None
        self.status = ConnectorStatus.DISCONNECTED

    def test_connection(self) -> bool:
        """
        Validate credentials by performing a lightweight asset search.

        Calls ``SearchAllResources`` with ``page_size=1`` to confirm the
        service-account credentials are valid and the project is accessible.
        """
        from google.cloud import asset_v1  # type: ignore[import-untyped]

        try:
            project_id = self.auth.credentials["project_id"]
            request = asset_v1.SearchAllResourcesRequest(
                scope=f"projects/{project_id}",
                page_size=1,
            )
            pager = self._asset_client.search_all_resources(  # type: ignore[union-attr]
                request=request
            )
            # Consume one result to verify the call succeeds.
            next(iter(pager))
            return True
        except StopIteration:
            # No resources but credentials are valid.
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
        Fetch GCP resources as normalised assets.

        Args:
            resource_type: GCP asset type filter
                (e.g. ``"compute.googleapis.com/Instance"``).
            limit: Maximum number of resources to return.

        Yields:
            ``ParsedAsset`` objects.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_tags(self, resource_id: str) -> Dict[str, str]:
        """
        Retrieve labels for a GCP resource.

        Args:
            resource_id: GCP resource name
                (e.g. ``"//compute.googleapis.com/projects/.../instances/..."``).

        Returns:
            Dict mapping label key to label value.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_owner_from_tags(
        self,
        resource_id: str,
        owner_tag_keys: Optional[List[str]] = None,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Derive owner information from GCP resource labels.

        Args:
            resource_id: GCP resource name.
            owner_tag_keys: Ordered list of label keys to check.
                Defaults to ``DEFAULT_OWNER_TAG_KEYS``.

        Returns:
            ``ParsedOwnerMapping`` if an owner label is found,
            ``None`` otherwise.
        """
        raise NotImplementedError("Community contribution welcome!")

    # -- parse helper ----------------------------------------------------------

    def _parse_resource(self, raw: Dict[str, Any]) -> ParsedAsset:
        """
        Map a raw GCP Cloud Asset resource to ``ParsedAsset``.

        Args:
            raw: Serialised ``ResourceSearchResult`` from the Cloud Asset API.

        Returns:
            Normalised ``ParsedAsset``.
        """
        labels: Dict[str, str] = raw.get("labels") or {}
        return ParsedAsset(
            hostname=raw.get("display_name") or raw.get("name"),
            asset_type=raw.get("asset_type"),
            environment=labels.get("environment") or labels.get("env"),
            criticality=labels.get("criticality"),
            owner_email=labels.get("owner"),
            department=labels.get("department"),
            business_unit=labels.get("business-unit"),
            cost_center=labels.get("cost-center"),
            location=raw.get("location"),
            extra={
                "resource_name": raw.get("name"),
                "project": raw.get("project"),
                "asset_type": raw.get("asset_type"),
                "state": raw.get("state"),
                "parent_asset_type": raw.get("parent_asset_type"),
                "labels": labels,
            },
        )
