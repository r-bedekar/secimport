"""
ServiceNow CMDB Connector.

API Docs: https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedAsset
from .base import BaseCMDBConnector


class ServiceNowConnector(BaseCMDBConnector):
    """
    ServiceNow CMDB Table API connector.

    Supports both basic authentication (username/password) and OAuth 2.0
    bearer-token authentication.

    Usage::

        from secimport.connectors.cmdb import ServiceNowConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://myinstance.service-now.com")
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "admin", "password": "secret"},
        )

        with ServiceNowConnector(config, auth) as snow:
            for asset in snow.get_assets(limit=100):
                print(asset.hostname, asset.operating_system)

    OAuth 2.0 example::

        auth = AuthConfig(
            auth_type="oauth2",
            credentials={"access_token": "eyJhbGciOiJ..."},
        )

        with ServiceNowConnector(config, auth) as snow:
            asset = snow.get_asset_by_id("sys_id_here")
    """

    name: ClassVar[str] = "servicenow"
    vendor: ClassVar[str] = "ServiceNow"
    description: ClassVar[str] = "ServiceNow CMDB"
    auth_types: ClassVar[Tuple[str, ...]] = ("basic", "oauth2")

    _test_endpoint: ClassVar[str] = "/api/now/table/sys_user?sysparm_limit=1"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "table_api": "/api/now/table/{table}",
        "cmdb_api": "/api/now/cmdb/instance/{class_name}",
        "ci_server": "/api/now/table/cmdb_ci_server",
    }

    def _auth_headers(self) -> Dict[str, str]:
        """Return auth headers.

        For OAuth 2.0, sends a Bearer token. Basic auth is handled by
        ``BaseConnector._auth_credentials``.

        Returns:
            Dict with authorization headers.
        """
        if self.auth.auth_type == "oauth2":
            token = self.auth.credentials["access_token"]
            return {"Authorization": f"Bearer {token}"}
        return {}

    def get_assets(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[ParsedAsset]:
        """Fetch CIs from ServiceNow.  GET /api/now/table/cmdb_ci_server"""
        raise NotImplementedError("Community contribution welcome!")

    def get_asset_by_id(self, asset_id: str) -> Optional[ParsedAsset]:
        """Get a single CI by sys_id.  GET /api/now/table/cmdb_ci/{sys_id}"""
        raise NotImplementedError("Community contribution welcome!")

    def search_assets(
        self,
        query: str,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedAsset]:
        """Search CIs via sysparm_query.  GET /api/now/table/cmdb_ci?sysparm_query=..."""
        raise NotImplementedError("Community contribution welcome!")

    def get_relationships(self, asset_id: str) -> List[Dict[str, Any]]:
        """Get CI relationships.  GET /api/now/cmdb/instance/{class_name}/{sys_id}/relations"""
        raise NotImplementedError("Community contribution welcome!")

    def _parse_asset(self, raw: Dict[str, Any]) -> ParsedAsset:
        """Map a ServiceNow CI record to ``ParsedAsset``.

        ServiceNow field mapping:
            - ``name``            -> ``hostname``
            - ``ip_address``      -> ``ip_address``
            - ``mac_address``     -> ``mac_address``
            - ``serial_number``   -> ``serial_number``
            - ``asset_tag``       -> ``asset_tag``
            - ``sys_class_name``  -> ``asset_type``
            - ``environment``     -> ``environment``
            - ``os``              -> ``operating_system``
            - ``os_version``      -> ``os_version``
            - ``location.name``   -> ``location``
            - ``assigned_to``     -> ``owner_name``
            - ``department``      -> ``department``

        Args:
            raw: Raw JSON dict from the ServiceNow Table API.

        Returns:
            Normalized ``ParsedAsset``.
        """
        # ``location`` and ``assigned_to`` may be nested link objects
        location = raw.get("location", {})
        if isinstance(location, dict):
            location = location.get("name") or location.get("display_value")

        assigned_to = raw.get("assigned_to", {})
        if isinstance(assigned_to, dict):
            assigned_to = (
                assigned_to.get("display_value") or assigned_to.get("name")
            )

        department = raw.get("department", {})
        if isinstance(department, dict):
            department = (
                department.get("display_value") or department.get("name")
            )

        return ParsedAsset(
            hostname=raw.get("name"),
            ip_address=raw.get("ip_address"),
            mac_address=raw.get("mac_address"),
            serial_number=raw.get("serial_number"),
            asset_tag=raw.get("asset_tag"),
            asset_type=raw.get("sys_class_name"),
            environment=raw.get("environment"),
            operating_system=raw.get("os"),
            os_version=raw.get("os_version"),
            location=location,
            owner_name=assigned_to,
            department=department,
            extra=raw,
        )
