"""Qualys vulnerability CSV parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from ..base import BaseParser


class QualysVulnParser(BaseParser):
    """Parse Qualys VM CSV exports into ParsedVulnerability."""

    name: ClassVar[str] = "qualys_vuln"
    source: ClassVar[str] = "qualys"
    data_type: ClassVar[str] = "vulnerability"
    description: ClassVar[str] = "Qualys VM vulnerability CSV export"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "QID",
        "Severity",
        "IP",
        "DNS",
        "Title",
        "Vuln Status",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "QID": "scanner_id",
        "CVE ID": "cve_id",
        "Title": "title",
        "Severity": "severity",
        "CVSS Base": "cvss_score",
        "Threat": "description",
        "Solution": "solution",
        "DNS": "hostname",
        "IP": "ip_address",
        "Port": "port",
        "Protocol": "protocol",
        "First Detected": "first_detected",
        "Last Detected": "last_detected",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedVulnerability:
        mapped = dict(row)
        extra = mapped.pop("extra", {})

        # Normalize severity
        mapped["severity"] = normalize_severity(mapped.get("severity"), "qualys")

        # Coerce numeric fields
        cvss = mapped.get("cvss_score")
        mapped["cvss_score"] = float(cvss) if cvss else None

        port = mapped.get("port")
        mapped["port"] = int(port) if port else None

        # Ensure title is present
        if not mapped.get("title"):
            mapped["title"] = f"QID-{mapped.get('scanner_id', 'unknown')}"

        mapped["extra"] = extra
        return ParsedVulnerability(**mapped)
