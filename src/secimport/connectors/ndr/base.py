"""
Base class for NDR (Network Detection and Response) connectors.

Extend this for: Darktrace, ExtraHop, Vectra, etc.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

from ...models.base import ParsedNetworkObservation
from ..base import BaseConnector


class BaseNDRConnector(BaseConnector):
    """
    Base class for NDR connectors.

    NDR tools passively observe network traffic and provide device
    classification, network topology, and anomaly detection.

    Subclass contract:
        * Override ``_auth_headers`` / ``_test_endpoint`` as needed.
        * Implement ``get_devices``, ``get_device_by_ip``, ``get_alerts``.
        * Implement ``_parse_device``.
    """

    @abstractmethod
    def get_devices(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[ParsedNetworkObservation]:
        """Fetch observed network devices."""
        ...

    @abstractmethod
    def get_device_by_ip(
        self, ip_address: str
    ) -> Optional[ParsedNetworkObservation]:
        """Look up a device by IP address."""
        ...

    @abstractmethod
    def get_alerts(
        self,
        since: Optional[datetime] = None,
        severity: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Fetch network anomaly alerts."""
        ...

    @abstractmethod
    def _parse_device(
        self, raw: Dict[str, Any]
    ) -> ParsedNetworkObservation:
        """Map raw API data to ``ParsedNetworkObservation``."""
        ...
