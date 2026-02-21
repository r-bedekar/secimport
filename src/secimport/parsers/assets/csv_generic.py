"""Generic asset CSV/Excel parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedAsset
from ..base import BaseParser


class GenericAssetParser(BaseParser):
    """Parse generic asset CSV/Excel exports into ParsedAsset."""

    name: ClassVar[str] = "generic_asset"
    source: ClassVar[str] = "generic"
    data_type: ClassVar[str] = "asset"
    description: ClassVar[str] = "Generic asset CSV/Excel with standard column names"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "Hostname",
        "IP Address",
        "Asset Type",
        "Owner",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        # Identifiers
        "Hostname": "hostname",
        "Host": "hostname",
        "Computer Name": "hostname",
        "Server Name": "hostname",
        "IP": "ip_address",
        "IP Address": "ip_address",
        "MAC": "mac_address",
        "MAC Address": "mac_address",
        "Serial": "serial_number",
        "Serial Number": "serial_number",
        "Asset Tag": "asset_tag",
        # Classification
        "Type": "asset_type",
        "Asset Type": "asset_type",
        "Category": "asset_type",
        "Environment": "environment",
        "Env": "environment",
        "Criticality": "criticality",
        # Ownership
        "Owner": "owner_email",
        "Owner Email": "owner_email",
        "Owner Name": "owner_name",
        "Department": "department",
        "Dept": "department",
        "Business Unit": "business_unit",
        "BU": "business_unit",
        "Cost Center": "cost_center",
        # Technical
        "OS": "operating_system",
        "Operating System": "operating_system",
        "OS Version": "os_version",
        "Location": "location",
        "Site": "location",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedAsset:
        mapped = dict(row)
        extra = mapped.pop("extra", {})
        mapped["extra"] = extra
        return ParsedAsset(**mapped)
