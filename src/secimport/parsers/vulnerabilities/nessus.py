"""Nessus vulnerability CSV parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from ..base import BaseParser


class NessusVulnParser(BaseParser):
    """Parse Nessus CSV exports into ParsedVulnerability."""

    name: ClassVar[str] = "nessus_vuln"
    source: ClassVar[str] = "nessus"
    data_type: ClassVar[str] = "vulnerability"
    description: ClassVar[str] = "Nessus vulnerability CSV export"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "Plugin ID",
        "Risk",
        "Host",
        "Name",
        "Synopsis",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "Plugin ID": "scanner_id",
        "CVE": "cve_id",
        "Name": "title",
        "Risk": "severity",
        "CVSS v3.0 Base Score": "cvss_score",
        "CVSS v2.0 Base Score": "cvss_score_v2",
        "Synopsis": "description",
        "Solution": "solution",
        "Host": "hostname",
        "IP Address": "ip_address",
        "Port": "port",
        "Protocol": "protocol",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedVulnerability:
        mapped = dict(row)
        extra = mapped.pop("extra", {})

        # Normalize severity
        mapped["severity"] = normalize_severity(mapped.get("severity"), "nessus")

        # Prefer CVSS v3, fall back to v2
        cvss = mapped.pop("cvss_score", None) or mapped.pop("cvss_score_v2", None)
        extra.pop("cvss_score_v2", None)
        mapped["cvss_score"] = float(cvss) if cvss else None

        port = mapped.get("port")
        mapped["port"] = int(port) if port else None

        if not mapped.get("title"):
            mapped["title"] = f"Plugin-{mapped.get('scanner_id', 'unknown')}"

        mapped["extra"] = extra
        return ParsedVulnerability(**mapped)
