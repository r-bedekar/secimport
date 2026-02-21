"""Rapid7 InsightVM vulnerability CSV parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from ..base import BaseParser


class Rapid7VulnParser(BaseParser):
    """Parse Rapid7 InsightVM CSV exports into ParsedVulnerability."""

    name: ClassVar[str] = "rapid7_vuln"
    source: ClassVar[str] = "rapid7"
    data_type: ClassVar[str] = "vulnerability"
    description: ClassVar[str] = "Rapid7 InsightVM vulnerability CSV export"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "Vulnerability ID",
        "Risk Score",
        "Asset IP Address",
        "Vulnerability Title",
        "Exploits",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "Vulnerability ID": "scanner_id",
        "CVE IDs": "cve_id",
        "Vulnerability Title": "title",
        "Severity": "severity",
        "CVSS Score": "cvss_score",
        "Description": "description",
        "Solution": "solution",
        "Asset Name": "hostname",
        "Asset IP Address": "ip_address",
        "Service Port": "port",
        "Service Protocol": "protocol",
        "First Found": "first_detected",
        "Last Found": "last_detected",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedVulnerability:
        mapped = dict(row)
        extra = mapped.pop("extra", {})

        mapped["severity"] = normalize_severity(mapped.get("severity"), "rapid7")

        cvss = mapped.get("cvss_score")
        mapped["cvss_score"] = float(cvss) if cvss else None

        port = mapped.get("port")
        mapped["port"] = int(port) if port else None

        if not mapped.get("title"):
            mapped["title"] = f"Vuln-{mapped.get('scanner_id', 'unknown')}"

        mapped["extra"] = extra
        return ParsedVulnerability(**mapped)
