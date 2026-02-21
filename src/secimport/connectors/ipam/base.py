"""
Base class for IPAM (IP Address Management) connectors.

Extend this for: Infoblox, NetBox, SolarWinds, phpIPAM, etc.
"""

from abc import abstractmethod
from typing import Any, Dict, Iterator, Optional

from ...models.base import ParsedOwnerMapping
from ..base import BaseConnector


class BaseIPAMConnector(BaseConnector):
    """
    Base class for all IPAM API connectors.

    Inherits connection plumbing (``connect``, ``test_connection``,
    ``disconnect``, auth hooks) from ``BaseConnector``.

    Subclass contract:
        * Override ``_auth_headers`` / ``_test_endpoint`` as needed.
        * Implement ``get_subnets``, ``get_ip_addresses``.
        * Implement ``get_owner_for_ip``, ``get_owner_for_subnet``.
        * Implement ``_parse_owner_mapping`` to map raw API data to the model.
    """

    # -- abstract data methods -------------------------------------------------

    @abstractmethod
    def get_subnets(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get subnets / networks from the IPAM system.

        Args:
            limit: Maximum number of subnets to return.

        Yields:
            Subnet dicts from the IPAM API.
        """
        ...

    @abstractmethod
    def get_ip_addresses(
        self,
        subnet: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get IP address records from the IPAM system.

        Args:
            subnet: Filter by subnet in CIDR notation (e.g. ``10.0.0.0/24``).
            limit: Maximum number of addresses to return.

        Yields:
            IP address dicts from the IPAM API.
        """
        ...

    @abstractmethod
    def get_owner_for_ip(
        self,
        ip_address: str,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Look up the owner of a specific IP address.

        Args:
            ip_address: The IP address to query (e.g. ``10.0.0.5``).

        Returns:
            ``ParsedOwnerMapping`` if ownership data is found, else ``None``.
        """
        ...

    @abstractmethod
    def get_owner_for_subnet(
        self,
        subnet: str,
    ) -> Optional[ParsedOwnerMapping]:
        """
        Look up the owner of a subnet / network.

        Args:
            subnet: Subnet in CIDR notation (e.g. ``10.0.0.0/24``).

        Returns:
            ``ParsedOwnerMapping`` if ownership data is found, else ``None``.
        """
        ...

    @abstractmethod
    def _parse_owner_mapping(self, raw: Dict[str, Any]) -> ParsedOwnerMapping:
        """
        Map a single raw API record to ``ParsedOwnerMapping``.

        Each IPAM system stores ownership data differently (extensible
        attributes, tenants, custom fields, etc.).  Concrete connectors
        implement this to normalize their format.

        Args:
            raw: Raw dict from the IPAM API response.

        Returns:
            A normalized ``ParsedOwnerMapping``.
        """
        ...
