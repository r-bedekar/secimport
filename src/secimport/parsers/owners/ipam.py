"""IPAM owner mapping CSV export parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedOwnerMapping
from ..base import BaseParser


class IPAMOwnerParser(BaseParser):
    """Parse IPAM export CSV files into ParsedOwnerMapping."""

    name: ClassVar[str] = "ipam_owner"
    source: ClassVar[str] = "ipam"
    data_type: ClassVar[str] = "owner"
    description: ClassVar[str] = "IPAM (Infoblox/NetBox/SolarWinds) owner mapping CSV export"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "Network",
        "Network View",
        "Comment",
        "EA-Site",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "Address": "ip_address",
        "IP Address": "ip_address",
        "Network": "subnet",
        "Subnet": "subnet",
        "CIDR": "ip_range",
        "Network View": "source_system",
        "Comment": "owner_name",
        "EA-Site": "location",
        "EA-Department": "department",
        "EA-Owner": "owner_email",
        "EA-Business Unit": "business_unit",
        # NetBox columns
        "Prefix": "ip_range",
        "Tenant": "business_unit",
        "Description": "owner_name",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedOwnerMapping:
        mapped = dict(row)
        extra = mapped.pop("extra", {})

        mapped.setdefault("source_system", "IPAM")

        conf = mapped.get("confidence")
        if conf:
            try:
                mapped["confidence"] = float(conf)
            except (ValueError, TypeError):
                mapped["confidence"] = 0.8
        else:
            mapped["confidence"] = 0.8

        mapped["extra"] = extra
        return ParsedOwnerMapping(**mapped)
