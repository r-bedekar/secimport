"""
VMware Carbon Black Cloud Connector.

API Docs: https://developer.carbonblack.com/reference/carbon-black-cloud/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedEndpoint, ParsedVulnerability
from .base import BaseEDRConnector


class CarbonBlackConnector(BaseEDRConnector):
    """VMware Carbon Black Cloud EDR connector."""

    name: ClassVar[str] = "carbon_black"
    vendor: ClassVar[str] = "VMware"
    description: ClassVar[str] = "VMware Carbon Black Cloud EDR"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key",)

    _test_endpoint: ClassVar[str] = "/appservices/v6/orgs/{org_key}/devices/_search"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "devices": "/appservices/v6/orgs/{org_key}/devices/_search",
        "alerts": "/api/alerts/v7/orgs/{org_key}/alerts/_search",
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "X-Auth-Token": (
                f"{self.auth.credentials.get('api_secret_key', '')}/"
                f"{self.auth.credentials.get('api_id', '')}"
            ),
        }

    def get_endpoints(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
        status_filter: Optional[str] = None,
    ) -> Iterator[ParsedEndpoint]:
        raise NotImplementedError("Community contribution welcome!")

    def get_endpoint_by_id(
        self, endpoint_id: str
    ) -> Optional[ParsedEndpoint]:
        raise NotImplementedError("Community contribution welcome!")

    def get_detections(
        self,
        since: Optional[datetime] = None,
        severity: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        raise NotImplementedError("Community contribution welcome!")

    def get_policy_compliance(
        self, limit: Optional[int] = None
    ) -> Iterator[Dict[str, Any]]:
        raise NotImplementedError("Community contribution welcome!")

    def _parse_endpoint(self, raw: Dict[str, Any]) -> ParsedEndpoint:
        return ParsedEndpoint(
            hostname=raw.get("name"),
            ip_address=raw.get("last_internal_ip_address"),
            mac_address=raw.get("mac_address"),
            device_id=str(raw.get("id", "")),
            agent_version=raw.get("sensor_version"),
            agent_status=raw.get("status"),
            operating_system=raw.get("os"),
            os_version=raw.get("os_version"),
            policy_name=raw.get("policy_name"),
            source_system="carbon_black",
            extra=raw,
        )
