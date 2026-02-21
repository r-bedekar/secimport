"""ServiceNow CMDB asset CSV export parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedAsset
from ..base import BaseParser


class ServiceNowAssetParser(BaseParser):
    """Parse ServiceNow CMDB CSV exports into ParsedAsset."""

    name: ClassVar[str] = "servicenow_asset"
    source: ClassVar[str] = "servicenow"
    data_type: ClassVar[str] = "asset"
    description: ClassVar[str] = "ServiceNow CMDB asset CSV export"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "sys_id",
        "name",
        "sys_class_name",
        "assigned_to",
        "u_environment",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "name": "hostname",
        "ip_address": "ip_address",
        "mac_address": "mac_address",
        "serial_number": "serial_number",
        "asset_tag": "asset_tag",
        "sys_class_name": "asset_type",
        "u_environment": "environment",
        "u_criticality": "criticality",
        "assigned_to": "owner_name",
        "assigned_to.email": "owner_email",
        "department": "department",
        "company": "business_unit",
        "cost_center": "cost_center",
        "os": "operating_system",
        "os_version": "os_version",
        "location": "location",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedAsset:
        mapped = dict(row)
        extra = mapped.pop("extra", {})
        mapped["extra"] = extra
        return ParsedAsset(**mapped)
