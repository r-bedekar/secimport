"""
Base class for cloud provider connectors.

Extend this for: AWS, Azure, GCP, etc.

Cloud connectors use native SDKs (boto3, azure-identity, google-cloud-asset)
instead of httpx.  Each concrete connector overrides ``connect()`` and
``disconnect()`` to manage its SDK client lifecycle.
"""

import logging
from abc import abstractmethod
from typing import Any, ClassVar, Dict, Iterator, List, Optional

from ...models.base import ParsedAsset, ParsedOwnerMapping
from ..base import AuthConfig, BaseConnector, ConnectionConfig, ConnectorStatus

logger = logging.getLogger("secimport.connectors.cloud")


class BaseCloudConnector(BaseConnector):
    """
    Base class for all cloud-provider API connectors.

    Inherits auth validation, auto-registration, and context-manager
    support from ``BaseConnector``.  Because cloud connectors talk to
    vendor SDKs rather than plain HTTP APIs, each subclass **must**
    override ``connect()`` and ``disconnect()`` to set up and tear down
    its SDK clients.

    Subclass contract:
        * Override ``connect()`` to create SDK clients.
        * Override ``disconnect()`` to release SDK clients.
        * Override ``test_connection()`` with an SDK health-check call.
        * Implement ``get_resources``, ``get_tags``, ``get_owner_from_tags``.
        * Implement ``_parse_resource`` to map raw API data to the model.
    """

    # Cloud connectors do not use httpx at all; disable the base-class
    # ``_test_endpoint`` since ``test_connection`` is fully overridden.
    _test_endpoint: ClassVar[str] = ""

    # -- init override ---------------------------------------------------------

    def __init__(
        self,
        connection: ConnectionConfig,
        auth: AuthConfig,
    ) -> None:
        """Initialise the cloud connector.

        Args:
            connection: Connection configuration (``base_url`` may be unused).
            auth: Authentication configuration with SDK credentials.
        """
        # Validate auth_type against allowed types (from BaseConnector.__init__)
        if auth.auth_type not in self.auth_types:
            raise ValueError(
                f"{self.name} connector does not support auth_type={auth.auth_type!r}. "
                f"Supported: {self.auth_types}"
            )
        self.connection = connection
        self.auth = auth
        self.status: str = ConnectorStatus.DISCONNECTED
        # Cloud connectors do NOT use httpx; leave _client as None.
        self._client = None

    # -- abstract data methods -------------------------------------------------

    @abstractmethod
    def get_resources(
        self,
        resource_type: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedAsset]:
        """
        Fetch cloud resources as normalised assets.

        Args:
            resource_type: Cloud-specific type filter
                (e.g. ``"AWS::EC2::Instance"``).
            limit: Maximum number of resources to return.

        Yields:
            ``ParsedAsset`` objects.
        """
        ...

    @abstractmethod
    def get_tags(self, resource_id: str) -> Dict[str, str]:
        """
        Retrieve tags / labels for a single resource.

        Args:
            resource_id: Cloud-specific resource identifier (ARN, resource ID, etc.).

        Returns:
            Dict mapping tag key to tag value.
        """
        ...

    @abstractmethod
    def get_owner_from_tags(
        self,
        resource_id: str,
        owner_tag_keys: Optional[List[str]] = None,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Derive an owner mapping from a resource's tags.

        Args:
            resource_id: Cloud-specific resource identifier.
            owner_tag_keys: Ordered list of tag keys to check for owner info.
                Falls back to a connector-specific default list when ``None``.

        Returns:
            ``ParsedOwnerMapping`` if an owner tag is found, ``None`` otherwise.
        """
        ...

    # -- parse helper ----------------------------------------------------------

    @abstractmethod
    def _parse_resource(self, raw: Dict[str, Any]) -> ParsedAsset:
        """Map a single raw SDK record to ``ParsedAsset``."""
        ...
