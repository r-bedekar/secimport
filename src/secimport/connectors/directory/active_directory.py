"""
Microsoft Active Directory Connector (LDAP).

API Docs: https://ldap3.readthedocs.io/

Status: STUB - Community contribution welcome!
"""

import logging
from typing import Any, ClassVar, Dict, Iterator, Optional, Tuple

from ...models.base import ParsedAsset
from ..base import AuthConfig, ConnectionConfig, ConnectorStatus
from .base import BaseDirectoryConnector

logger = logging.getLogger("secimport.connectors")


class ActiveDirectoryConnector(BaseDirectoryConnector):
    """
    Microsoft Active Directory connector via LDAP.

    Uses ``ldap3`` to bind and query an on-premises Active Directory
    domain controller.  Because AD uses LDAP rather than HTTP, this
    connector overrides ``connect()`` and ``disconnect()`` to manage
    an ``ldap3.Connection`` instead of an ``httpx.Client``.

    Usage::

        from secimport.connectors.directory import ActiveDirectoryConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="ldap://dc01.example.com")
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "CN=svc,OU=Service,DC=example,DC=com",
                          "password": "s3cret"},
        )

        with ActiveDirectoryConnector(config, auth) as ad:
            for user in ad.get_users(limit=10):
                print(user["cn"])
    """

    name: ClassVar[str] = "active_directory"
    vendor: ClassVar[str] = "Microsoft"
    description: ClassVar[str] = "Microsoft Active Directory via LDAP"
    auth_types: ClassVar[Tuple[str, ...]] = ("basic",)

    # Not used -- AD is queried over LDAP, not HTTP.
    _test_endpoint: ClassVar[str] = "/"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "users": "OU=Users,DC=example,DC=com",
        "computers": "OU=Computers,DC=example,DC=com",
    }

    def __init__(
        self,
        connection: ConnectionConfig,
        auth: AuthConfig,
    ) -> None:
        super().__init__(connection, auth)
        self._ldap_connection: Any = None

    # -- connect / disconnect (LDAP, not HTTP) ---------------------------------

    def connect(self) -> bool:
        """
        Establish an LDAP bind to Active Directory.

        Uses ``ldap3.Server`` and ``ldap3.Connection`` to bind with
        the credentials provided in ``self.auth``.
        """
        # ldap3 is an optional dependency; import at call-time so the
        # rest of the library works without it installed.
        import ldap3  # type: ignore[import-untyped]

        server = ldap3.Server(
            self.connection.base_url,
            get_info=ldap3.ALL,
            connect_timeout=self.connection.timeout,
        )
        conn = ldap3.Connection(
            server,
            user=self.auth.credentials["username"],
            password=self.auth.credentials["password"],
            auto_bind=False,
        )
        try:
            if conn.bind():
                self._ldap_connection = conn
                self.status = ConnectorStatus.CONNECTED
                logger.info(
                    "%s: bound to %s", self.name, self.connection.base_url
                )
                return True
            self.status = ConnectorStatus.ERROR
            raise ConnectionError(
                f"LDAP bind failed: {conn.result}"
            )
        except ConnectionError:
            raise
        except Exception as exc:
            self.status = ConnectorStatus.ERROR
            raise ConnectionError(
                f"Failed to connect to {self.name}: {exc}"
            ) from exc

    def disconnect(self) -> None:
        """Unbind from the LDAP directory and clean up."""
        if self._ldap_connection is not None:
            try:
                self._ldap_connection.unbind()
            except Exception:  # noqa: BLE001
                pass
            self._ldap_connection = None
        # Skip BaseConnector.disconnect() httpx cleanup -- we have no _client.
        self.status = ConnectorStatus.DISCONNECTED

    def test_connection(self) -> bool:
        """Check that the LDAP connection is still bound."""
        if self._ldap_connection is None:
            return False
        return self._ldap_connection.bound

    def get_rate_limit_status(self) -> Dict[str, Any]:
        """LDAP directories do not expose HTTP-style rate limits."""
        return {"limit": None, "remaining": None, "note": "LDAP has no rate limit API"}

    # -- data methods (stubs) --------------------------------------------------

    def get_users(
        self,
        limit: Optional[int] = None,
        search_filter: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Query Active Directory for user objects.

        LDAP search base: ``ENDPOINTS["users"]``
        Default filter: ``(objectClass=user)``
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_groups(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Query Active Directory for group objects.

        LDAP search base: ``ENDPOINTS["users"]``
        Default filter: ``(objectClass=group)``
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_computers(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedAsset]:
        """
        Query Active Directory for computer objects.

        LDAP search base: ``ENDPOINTS["computers"]``
        Default filter: ``(objectClass=computer)``
        """
        raise NotImplementedError("Community contribution welcome!")

    def search(
        self,
        query: str,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Run a raw LDAP filter against Active Directory.

        Args:
            query: An LDAP filter string, e.g. ``(sAMAccountName=jdoe*)``.
            limit: Maximum entries to return.
        """
        raise NotImplementedError("Community contribution welcome!")

    # -- parse helper ----------------------------------------------------------

    def _parse_computer(self, raw: Dict[str, Any]) -> ParsedAsset:
        """
        Map an Active Directory computer entry to ``ParsedAsset``.

        Expected AD attributes::

            cn, dNSHostName, operatingSystem, operatingSystemVersion,
            managedBy, location, distinguishedName, description
        """
        return ParsedAsset(
            hostname=raw.get("dNSHostName") or raw.get("cn"),
            operating_system=raw.get("operatingSystem"),
            os_version=raw.get("operatingSystemVersion"),
            owner_name=raw.get("managedBy"),
            location=raw.get("location"),
            asset_type="Computer",
            extra={
                "distinguished_name": raw.get("distinguishedName"),
                "cn": raw.get("cn"),
                "description": raw.get("description"),
                "when_created": raw.get("whenCreated"),
                "when_changed": raw.get("whenChanged"),
                "source": "active_directory",
            },
        )
