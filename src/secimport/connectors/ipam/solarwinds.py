"""
SolarWinds IPAM API Connector.

API Docs: https://www.solarwinds.com/documentation

Status: STUB - Community contribution welcome!
"""

from typing import Any, ClassVar, Dict, Iterator, Optional, Tuple

from ...models.base import ParsedOwnerMapping
from .base import BaseIPAMConnector


class SolarWindsConnector(BaseIPAMConnector):
    """
    SolarWinds IPAM connector via the SolarWinds Information Service (SWIS).

    Uses the SWIS REST API with HTTP basic authentication.  Data is retrieved
    through SWQL queries against the ``IPAM.Subnet`` and ``IPAM.IPNode`` entities.

    Usage::

        from secimport.connectors.ipam import SolarWindsConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(
            base_url="https://solarwinds.corp.local:17778",
            verify_ssl=False,
        )
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "admin", "password": "secret"},
        )

        with SolarWindsConnector(config, auth) as sw:
            for subnet in sw.get_subnets():
                print(subnet["Address"], subnet["CIDR"])
    """

    name: ClassVar[str] = "solarwinds"
    vendor: ClassVar[str] = "SolarWinds"
    description: ClassVar[str] = "SolarWinds IPAM"
    auth_types: ClassVar[Tuple[str, ...]] = ("basic",)

    _test_endpoint: ClassVar[str] = (
        "/SolarWinds/InformationService/v3/Json/Query"
    )

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "query": "/SolarWinds/InformationService/v3/Json/Query",
        "invoke": (
            "/SolarWinds/InformationService/v3/Json/Invoke/{entity}/{verb}"
        ),
    }

    def test_connection(self) -> bool:
        """Test SolarWinds SWIS connection with a lightweight SWQL query.

        The default ``_test_endpoint`` requires a query parameter, so we
        override ``test_connection`` to send a minimal SWQL query.
        """
        try:
            response = self._client.post(  # type: ignore[union-attr]
                self.ENDPOINTS["query"],
                json={"query": "SELECT TOP 1 NodeID FROM Orion.Nodes"},
            )
            return response.status_code == 200
        except Exception:
            return False

    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Return rate-limit info for SolarWinds.

        SolarWinds SWIS does not expose rate-limit headers.
        Throttling is managed server-side via IIS and the Orion platform.
        """
        return {
            "limit": None,
            "remaining": None,
            "note": (
                "SolarWinds SWIS has no standard rate-limit headers; "
                "throttling is managed server-side."
            ),
        }

    def get_subnets(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get subnets from SolarWinds IPAM via SWQL.

        POST /SolarWinds/InformationService/v3/Json/Query
        Body: {"query": "SELECT ... FROM IPAM.Subnet"}

        Args:
            limit: Maximum number of subnets to return.

        Yields:
            Subnet dicts from the SWIS query results.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_ip_addresses(
        self,
        subnet: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get IP node records from SolarWinds IPAM via SWQL.

        POST /SolarWinds/InformationService/v3/Json/Query
        Body: {"query": "SELECT ... FROM IPAM.IPNode WHERE SubnetId = ..."}

        Args:
            subnet: Filter by subnet (matched against the ``Address/CIDR`` fields).
            limit: Maximum number of IP records to return.

        Yields:
            IP node dicts from the SWIS query results.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_owner_for_ip(
        self,
        ip_address: str,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Look up the owner of an IP address via SolarWinds custom properties.

        POST /SolarWinds/InformationService/v3/Json/Query
        Body: {"query": "SELECT ... FROM IPAM.IPNode WHERE IPAddress = ..."}

        Args:
            ip_address: The IP address to query.

        Returns:
            ``ParsedOwnerMapping`` if custom properties contain ownership data,
            else ``None``.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_owner_for_subnet(
        self,
        subnet: str,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Look up the owner of a subnet via SolarWinds custom properties.

        POST /SolarWinds/InformationService/v3/Json/Query
        Body: {"query": "SELECT ... FROM IPAM.Subnet WHERE Address = ..."}

        Args:
            subnet: Subnet in CIDR notation (e.g. ``10.0.0.0/24``).

        Returns:
            ``ParsedOwnerMapping`` if custom properties contain ownership data,
            else ``None``.
        """
        raise NotImplementedError("Community contribution welcome!")

    def _parse_owner_mapping(self, raw: Dict[str, Any]) -> ParsedOwnerMapping:
        """
        Parse SolarWinds custom properties into a normalized owner mapping.

        SolarWinds stores custom metadata through Orion custom properties
        on nodes and subnets::

            {
                "Address": "10.0.0.0",
                "CIDR": 24,
                "CustomProperties": {
                    "Owner": "jdoe@corp.com",
                    "Department": "Engineering",
                    "Site": "NYC-DC1"
                }
            }

        Args:
            raw: Raw SolarWinds SWIS result dict.

        Returns:
            A normalized ``ParsedOwnerMapping``.
        """
        custom_props = raw.get("CustomProperties") or {}

        # Build CIDR notation from Address + CIDR fields
        address = raw.get("Address")
        cidr = raw.get("CIDR")
        subnet_cidr = f"{address}/{cidr}" if address and cidr is not None else None

        # For IP nodes, IPAddress is the field
        ip_address = raw.get("IPAddress") or raw.get("ip_address")

        return ParsedOwnerMapping(
            ip_address=ip_address,
            subnet=subnet_cidr,
            ip_range=subnet_cidr,
            owner_email=custom_props.get("Owner"),
            owner_name=custom_props.get("Owner"),
            department=custom_props.get("Department"),
            location=custom_props.get("Site"),
            source_system="solarwinds",
            confidence=0.8,
            extra=raw,
        )
