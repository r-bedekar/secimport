"""CrowdStrike Spotlight vulnerability CSV parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from ..base import BaseParser


class CrowdStrikeVulnParser(BaseParser):
    """Parse CrowdStrike Spotlight CSV exports into ParsedVulnerability."""

    name: ClassVar[str] = "crowdstrike_vuln"
    source: ClassVar[str] = "crowdstrike"
    data_type: ClassVar[str] = "vulnerability"
    description: ClassVar[str] = "CrowdStrike Spotlight vulnerability CSV export"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "Vulnerability ID",
        "CVE",
        "Severity",
        "Hostname",
        "Aid",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "Vulnerability ID": "scanner_id",
        "CVE": "cve_id",
        "Vulnerability Name": "title",
        "Severity": "severity",
        "CVSS Score": "cvss_score",
        "Description": "description",
        "Remediation": "solution",
        "Hostname": "hostname",
        "Local IP": "ip_address",
        "First Seen": "first_detected",
        "Last Seen": "last_detected",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedVulnerability:
        mapped = dict(row)
        extra = mapped.pop("extra", {})

        mapped["severity"] = normalize_severity(mapped.get("severity"), "generic")

        cvss = mapped.get("cvss_score")
        mapped["cvss_score"] = float(cvss) if cvss else None

        if not mapped.get("title"):
            mapped["title"] = f"Vuln-{mapped.get('scanner_id', 'unknown')}"

        mapped["extra"] = extra
        return ParsedVulnerability(**mapped)
