"""
BMC Helix ITSM / CMDB Connector.

API Docs: https://docs.bmc.com/docs/ars2102/rest-api

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedAsset
from .base import BaseCMDBConnector


class BMCHelixConnector(BaseCMDBConnector):
    """
    BMC Helix ITSM / CMDB REST API connector.

    Supports basic authentication and JWT token authentication.  For
    token auth, first obtain a JWT via ``POST /api/jwt/login`` and pass
    it as ``credentials["token"]``.

    Usage::

        from secimport.connectors.cmdb import BMCHelixConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://helix.example.com")
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "admin", "password": "secret"},
        )

        with BMCHelixConnector(config, auth) as bmc:
            for asset in bmc.get_assets(limit=50):
                print(asset.hostname, asset.asset_type)

    Token auth example::

        auth = AuthConfig(
            auth_type="token",
            credentials={"token": "eyJhbGciOiJ..."},
        )

        with BMCHelixConnector(config, auth) as bmc:
            results = bmc.search_assets("ServerType=Unix")
    """

    name: ClassVar[str] = "bmc_helix"
    vendor: ClassVar[str] = "BMC"
    description: ClassVar[str] = "BMC Helix ITSM / CMDB"
    auth_types: ClassVar[Tuple[str, ...]] = ("basic", "token")

    _test_endpoint: ClassVar[str] = "/api/arsys/v1/entry/HPD:Help Desk?limit=1"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "entries": "/api/arsys/v1/entry/{form}",
        "token": "/api/jwt/login",
    }

    def _auth_headers(self) -> Dict[str, str]:
        """Return auth headers.

        For token auth, sends a JWT authorization header. Basic auth is
        handled by ``BaseConnector._auth_credentials``.

        Returns:
            Dict with authorization headers.
        """
        if self.auth.auth_type == "token":
            token = self.auth.credentials["token"]
            return {"Authorization": f"AR-JWT {token}"}
        return {}

    def get_assets(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[ParsedAsset]:
        """Fetch CIs from BMC Helix.  GET /api/arsys/v1/entry/BMC.ASSET"""
        raise NotImplementedError("Community contribution welcome!")

    def get_asset_by_id(self, asset_id: str) -> Optional[ParsedAsset]:
        """Get a single CI by entry ID.  GET /api/arsys/v1/entry/BMC.ASSET/{id}"""
        raise NotImplementedError("Community contribution welcome!")

    def search_assets(
        self,
        query: str,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedAsset]:
        """Search CIs via qualification.  GET /api/arsys/v1/entry/BMC.ASSET?q=..."""
        raise NotImplementedError("Community contribution welcome!")

    def get_relationships(self, asset_id: str) -> List[Dict[str, Any]]:
        """Get CI relationships.  GET /api/arsys/v1/entry/BMC.CORE.CONFIG.REL"""
        raise NotImplementedError("Community contribution welcome!")

    def _parse_asset(self, raw: Dict[str, Any]) -> ParsedAsset:
        """Map a BMC Helix CI record to ``ParsedAsset``.

        BMC Helix field mapping (varies by form; common ``BMC.ASSET`` fields):
            - ``Name``                -> ``hostname``
            - ``IPAddress``           -> ``ip_address``
            - ``MACAddress``          -> ``mac_address``
            - ``SerialNumber``        -> ``serial_number``
            - ``AssetTag``            -> ``asset_tag``
            - ``AssetType``           -> ``asset_type``
            - ``Environment``         -> ``environment``
            - ``OperatingSystem``     -> ``operating_system``
            - ``OSVersion``           -> ``os_version``
            - ``Site``                -> ``location``
            - ``OwnerName``           -> ``owner_name``
            - ``Department``          -> ``department``
            - ``Company``             -> ``business_unit``

        Args:
            raw: Raw JSON dict from the BMC Helix REST API (``values`` payload).

        Returns:
            Normalized ``ParsedAsset``.
        """
        # BMC responses nest fields under a ``values`` key
        values = raw.get("values", raw)

        return ParsedAsset(
            hostname=values.get("Name"),
            ip_address=values.get("IPAddress"),
            mac_address=values.get("MACAddress"),
            serial_number=values.get("SerialNumber"),
            asset_tag=values.get("AssetTag"),
            asset_type=values.get("AssetType"),
            environment=values.get("Environment"),
            operating_system=values.get("OperatingSystem"),
            os_version=values.get("OSVersion"),
            location=values.get("Site"),
            owner_name=values.get("OwnerName"),
            department=values.get("Department"),
            business_unit=values.get("Company"),
            extra=raw,
        )
