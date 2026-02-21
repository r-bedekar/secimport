"""Tenable.io vulnerability CSV parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from ..base import BaseParser


class TenableVulnParser(BaseParser):
    """Parse Tenable.io CSV exports into ParsedVulnerability."""

    name: ClassVar[str] = "tenable_vuln"
    source: ClassVar[str] = "tenable"
    data_type: ClassVar[str] = "vulnerability"
    description: ClassVar[str] = "Tenable.io vulnerability CSV export"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "Plugin ID",
        "Severity",
        "Asset UUID",
        "Plugin Name",
        "Plugin Family",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "Plugin ID": "scanner_id",
        "CVE": "cve_id",
        "Plugin Name": "title",
        "Severity": "severity",
        "CVSS V3 Base Score": "cvss_score",
        "CVSS V2 Base Score": "cvss_score_v2",
        "Description": "description",
        "Solution": "solution",
        "Host": "hostname",
        "IP Address": "ip_address",
        "Port": "port",
        "Protocol": "protocol",
        "First Seen": "first_detected",
        "Last Seen": "last_detected",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedVulnerability:
        mapped = dict(row)
        extra = mapped.pop("extra", {})

        mapped["severity"] = normalize_severity(mapped.get("severity"), "tenable")

        cvss = mapped.pop("cvss_score", None) or mapped.pop("cvss_score_v2", None)
        extra.pop("cvss_score_v2", None)
        mapped["cvss_score"] = float(cvss) if cvss else None

        port = mapped.get("port")
        mapped["port"] = int(port) if port else None

        if not mapped.get("title"):
            mapped["title"] = f"Plugin-{mapped.get('scanner_id', 'unknown')}"

        mapped["extra"] = extra
        return ParsedVulnerability(**mapped)
