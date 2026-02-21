"""
NetBox IPAM / DCIM API Connector.

API Docs: https://demo.netbox.dev/static/docs/rest-api/overview/

Status: STUB - Community contribution welcome!
"""

from typing import Any, ClassVar, Dict, Iterator, Optional, Tuple

from ...models.base import ParsedOwnerMapping
from .base import BaseIPAMConnector


class NetBoxConnector(BaseIPAMConnector):
    """
    NetBox REST API connector for IPAM and DCIM data.

    Uses token-based authentication with the ``Authorization: Token xxx`` header
    scheme expected by the NetBox API.

    Usage::

        from secimport.connectors.ipam import NetBoxConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://netbox.corp.local")
        auth = AuthConfig(
            auth_type="token",
            credentials={"token": "your-netbox-api-token"},
        )

        with NetBoxConnector(config, auth) as nb:
            for prefix in nb.get_subnets():
                print(prefix["prefix"])
    """

    name: ClassVar[str] = "netbox"
    vendor: ClassVar[str] = "NetBox"
    description: ClassVar[str] = "NetBox IPAM / DCIM"
    auth_types: ClassVar[Tuple[str, ...]] = ("token",)

    _test_endpoint: ClassVar[str] = "/api/status/"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "prefixes": "/api/ipam/prefixes/",
        "ip_addresses": "/api/ipam/ip-addresses/",
        "tenants": "/api/tenancy/tenants/",
    }

    def _auth_headers(self) -> Dict[str, str]:
        """Return NetBox token authentication header."""
        return {"Authorization": f"Token {self.auth.credentials['token']}"}

    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Return rate-limit info for NetBox.

        NetBox does not enforce rate limits by default; they are
        optionally configured via ``LOGIN_RATE_LIMIT`` / plugins.
        """
        return {
            "limit": None,
            "remaining": None,
            "note": "NetBox has no default rate limits; check server configuration.",
        }

    def get_subnets(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get prefixes (subnets) from NetBox.

        GET /api/ipam/prefixes/?limit={limit}

        Args:
            limit: Maximum number of prefixes to return.

        Yields:
            Prefix dicts from the NetBox API.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_ip_addresses(
        self,
        subnet: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get IP address records from NetBox.

        GET /api/ipam/ip-addresses/?parent={subnet}&limit={limit}

        Args:
            subnet: Filter by parent prefix in CIDR notation (e.g. ``10.0.0.0/24``).
            limit: Maximum number of IP address records to return.

        Yields:
            IP address dicts from the NetBox API.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_owner_for_ip(
        self,
        ip_address: str,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Look up the owner of an IP address via its tenant in NetBox.

        GET /api/ipam/ip-addresses/?address={ip_address}

        Args:
            ip_address: The IP address to query.

        Returns:
            ``ParsedOwnerMapping`` if a tenant is assigned, else ``None``.
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_owner_for_subnet(
        self,
        subnet: str,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Look up the owner of a prefix via its tenant in NetBox.

        GET /api/ipam/prefixes/?prefix={subnet}

        Args:
            subnet: Prefix in CIDR notation (e.g. ``10.0.0.0/24``).

        Returns:
            ``ParsedOwnerMapping`` if a tenant is assigned, else ``None``.
        """
        raise NotImplementedError("Community contribution welcome!")

    def _parse_owner_mapping(self, raw: Dict[str, Any]) -> ParsedOwnerMapping:
        """
        Parse NetBox tenant and custom fields into a normalized owner mapping.

        NetBox associates ownership through the ``tenant`` object on prefixes
        and IP addresses, with optional ``custom_fields`` for extra metadata::

            {
                "address": "10.0.0.5/32",
                "tenant": {
                    "name": "Engineering",
                    "slug": "engineering"
                },
                "custom_fields": {
                    "owner_email": "jdoe@corp.com",
                    "department": "Platform"
                }
            }

        Args:
            raw: Raw NetBox object dict containing ``tenant`` / ``custom_fields``.

        Returns:
            A normalized ``ParsedOwnerMapping``.
        """
        tenant = raw.get("tenant") or {}
        custom_fields = raw.get("custom_fields") or {}

        # NetBox uses "address" for IPs (with mask) and "prefix" for subnets
        address = raw.get("address")
        prefix = raw.get("prefix")

        # Strip the mask from an address to get a bare IP
        ip_address = address.split("/")[0] if address else None

        return ParsedOwnerMapping(
            ip_address=ip_address,
            subnet=prefix,
            ip_range=prefix,
            owner_email=custom_fields.get("owner_email"),
            owner_name=custom_fields.get("owner_name"),
            department=custom_fields.get("department", tenant.get("name")),
            business_unit=tenant.get("name"),
            location=custom_fields.get("location"),
            source_system="netbox",
            confidence=0.85,
            extra=raw,
        )
