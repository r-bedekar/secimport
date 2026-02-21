"""Generic vulnerability CSV parser for unknown/custom formats."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from ..base import BaseParser


class GenericVulnParser(BaseParser):
    """Parse generic vulnerability CSVs with common column names."""

    name: ClassVar[str] = "generic_vuln"
    source: ClassVar[str] = "generic"
    data_type: ClassVar[str] = "vulnerability"
    description: ClassVar[str] = "Generic vulnerability CSV with standard column names"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "CVE",
        "Severity",
        "Title",
        "IP Address",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "ID": "scanner_id",
        "Scanner ID": "scanner_id",
        "CVE": "cve_id",
        "CVE ID": "cve_id",
        "Title": "title",
        "Name": "title",
        "Vulnerability": "title",
        "Severity": "severity",
        "Risk": "severity",
        "CVSS": "cvss_score",
        "CVSS Score": "cvss_score",
        "Description": "description",
        "Solution": "solution",
        "Remediation": "solution",
        "Hostname": "hostname",
        "Host": "hostname",
        "IP": "ip_address",
        "IP Address": "ip_address",
        "Port": "port",
        "Protocol": "protocol",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedVulnerability:
        mapped = dict(row)
        extra = mapped.pop("extra", {})

        mapped["severity"] = normalize_severity(mapped.get("severity"), "generic")

        cvss = mapped.get("cvss_score")
        mapped["cvss_score"] = float(cvss) if cvss else None

        port = mapped.get("port")
        mapped["port"] = int(port) if port else None

        if not mapped.get("title"):
            mapped["title"] = mapped.get("cve_id") or "Unknown Vulnerability"

        mapped["extra"] = extra
        return ParsedVulnerability(**mapped)
