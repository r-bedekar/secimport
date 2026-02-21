"""Generic owner mapping CSV/Excel parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedOwnerMapping
from ..base import BaseParser


class GenericOwnerParser(BaseParser):
    """Parse generic owner mapping CSV/Excel exports into ParsedOwnerMapping."""

    name: ClassVar[str] = "generic_owner"
    source: ClassVar[str] = "generic"
    data_type: ClassVar[str] = "owner"
    description: ClassVar[str] = "Generic owner mapping CSV/Excel"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "IP Address",
        "Owner",
        "Department",
        "Subnet",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "IP": "ip_address",
        "IP Address": "ip_address",
        "IP Range": "ip_range",
        "CIDR": "ip_range",
        "Subnet": "subnet",
        "Network": "subnet",
        "Hostname Pattern": "hostname_pattern",
        "Owner": "owner_email",
        "Owner Email": "owner_email",
        "Email": "owner_email",
        "Owner Name": "owner_name",
        "Name": "owner_name",
        "Department": "department",
        "Dept": "department",
        "Business Unit": "business_unit",
        "BU": "business_unit",
        "Location": "location",
        "Site": "location",
        "Source": "source_system",
        "Source System": "source_system",
        "Confidence": "confidence",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedOwnerMapping:
        mapped = dict(row)
        extra = mapped.pop("extra", {})

        # Coerce confidence to float
        conf = mapped.get("confidence")
        if conf:
            try:
                mapped["confidence"] = float(conf)
            except (ValueError, TypeError):
                mapped["confidence"] = 1.0

        mapped["extra"] = extra
        return ParsedOwnerMapping(**mapped)
