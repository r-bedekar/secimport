"""
Base connector class for all API integrations.

All connectors inherit from this and implement the abstract methods.
Community contributors: Create a new file in the appropriate folder
and implement these methods for your system.
"""

import logging
from abc import ABC
from typing import Any, ClassVar, Dict, Optional, Tuple, Type

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger("secimport.connectors")


class ConnectorStatus:
    """Connection status constants."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"


class ConnectionConfig(BaseModel):
    """Base configuration for connectors."""

    base_url: str
    verify_ssl: bool = True
    timeout: int = 30
    max_retries: int = 3


class AuthConfig(BaseModel):
    """Authentication configuration."""

    auth_type: str = Field(
        ...,
        description="Authentication method: api_key, basic, oauth2, token",
    )
    credentials: Dict[str, str] = Field(
        ...,
        description="Credentials dict, e.g. {'username': 'x', 'password': 'y'}",
    )


class ConnectorRegistry:
    """
    Registry for discovering available connectors.

    Community contributors: Your connector is automatically registered
    when its module is imported. Use ``ConnectorRegistry.list_connectors()``
    to discover all loaded connectors.
    """

    _connectors: Dict[str, Type["BaseConnector"]] = {}

    @classmethod
    def register(cls, connector_cls: Type["BaseConnector"]) -> Type["BaseConnector"]:
        """Register a connector class by its ``name``."""
        cls._connectors[connector_cls.name] = connector_cls
        return connector_cls

    @classmethod
    def get(cls, name: str) -> Optional[Type["BaseConnector"]]:
        """Look up a connector by name."""
        return cls._connectors.get(name)

    @classmethod
    def list_connectors(cls) -> Dict[str, Type["BaseConnector"]]:
        """Return all registered connectors."""
        return dict(cls._connectors)


class BaseConnector(ABC):
    """
    Abstract base class for all connectors.

    Provides shared connection plumbing so that concrete connectors
    only need to declare their auth headers, test endpoint, and
    domain-specific data methods.

    Subclass contract:
        * Set ``name``, ``vendor``, ``description``, ``auth_types``.
        * Override ``_auth_headers`` and/or ``_auth_credentials`` for auth.
        * Override ``_test_endpoint`` to point at a lightweight health-check URL.
        * Implement domain-specific data methods (defined in category bases).

    Example::

        class MySystemConnector(BaseConnector):
            name = "mysystem"
            vendor = "MyVendor"
            description = "My system connector"
            auth_types = ("api_key",)
            _test_endpoint = "/api/v1/status"

            def _auth_headers(self) -> Dict[str, str]:
                return {"X-Api-Key": self.auth.credentials["api_key"]}
    """

    # -- class-level metadata (override in subclasses) -------------------------

    name: ClassVar[str] = "base"
    vendor: ClassVar[str] = "Unknown"
    description: ClassVar[str] = "Base connector"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key",)

    #: Lightweight health-check URL used by ``test_connection()``.
    _test_endpoint: ClassVar[str] = "/"

    # -- auto-registration -----------------------------------------------------

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Auto-register concrete connectors and freeze auth_types."""
        super().__init_subclass__(**kwargs)
        # Convert mutable list to tuple if needed
        if isinstance(cls.auth_types, list):
            cls.auth_types = tuple(cls.auth_types)
        # Register non-abstract connectors
        if not getattr(cls, "__abstractmethods__", None) and cls.name != "base":
            ConnectorRegistry.register(cls)

    # -- init ------------------------------------------------------------------

    def __init__(
        self,
        connection: ConnectionConfig,
        auth: AuthConfig,
    ) -> None:
        if auth.auth_type not in self.auth_types:
            raise ValueError(
                f"{self.name} connector does not support auth_type={auth.auth_type!r}. "
                f"Supported: {self.auth_types}"
            )
        self.connection = connection
        self.auth = auth
        self.status: str = ConnectorStatus.DISCONNECTED
        self._client: Optional[httpx.Client] = None

    # -- auth hooks (override per connector) -----------------------------------

    def _auth_headers(self) -> Dict[str, str]:
        """Return auth-related HTTP headers. Override in subclass."""
        return {}

    def _auth_credentials(self) -> Optional[tuple]:
        """Return ``(username, password)`` for HTTP basic auth, or ``None``."""
        if self.auth.auth_type == "basic":
            return (
                self.auth.credentials["username"],
                self.auth.credentials["password"],
            )
        return None

    # -- shared connect / disconnect / test ------------------------------------

    def connect(self) -> bool:
        """
        Establish connection to the system.

        Builds an ``httpx.Client`` using ``_auth_headers`` / ``_auth_credentials``,
        then validates with ``test_connection``.

        Override this **only** if you need a non-standard flow (e.g. OAuth2 token
        exchange). Otherwise, just override ``_auth_headers``.
        """
        headers = {"Content-Type": "application/json", **self._auth_headers()}
        client = self._build_client(
            auth=self._auth_credentials(),
            headers=headers,
        )
        return self._connect_with_test(client)

    def disconnect(self) -> None:
        """Close connection and cleanup."""
        if self._client:
            self._client.close()
            self._client = None
        self.status = ConnectorStatus.DISCONNECTED

    def test_connection(self) -> bool:
        """Ping ``_test_endpoint`` and check for HTTP 200."""
        try:
            response = self._client.get(self._test_endpoint)  # type: ignore[union-attr]
            return response.status_code == 200
        except Exception:
            return False

    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Return current rate-limit info. Override for system-specific detail."""
        return {"limit": None, "remaining": None, "note": "Unknown"}

    # -- helpers for subclasses ------------------------------------------------

    def _build_client(
        self,
        *,
        auth: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Client:
        """
        Create an ``httpx.Client`` pre-configured from ``self.connection``.

        Subclasses call this in ``connect()`` instead of constructing
        the client manually every time.
        """
        return httpx.Client(
            base_url=self.connection.base_url,
            auth=auth,
            headers=headers or {},
            timeout=self.connection.timeout,
            verify=self.connection.verify_ssl,
        )

    def _connect_with_test(self, client: httpx.Client) -> bool:
        """
        Assign *client*, run ``test_connection``, and set status.

        Returns:
            True on success; raises ``ConnectionError`` on failure.
        """
        self._client = client
        try:
            if self.test_connection():
                self.status = ConnectorStatus.CONNECTED
                logger.info("%s: connected to %s", self.name, self.connection.base_url)
                return True
            self.disconnect()
            return False
        except Exception as exc:
            self.status = ConnectorStatus.ERROR
            self.disconnect()
            raise ConnectionError(f"Failed to connect to {self.name}: {exc}") from exc

    # -- context manager -------------------------------------------------------

    def __enter__(self) -> "BaseConnector":
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Any,
    ) -> None:
        self.disconnect()
