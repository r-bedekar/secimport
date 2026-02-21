"""OpenVAS vulnerability CSV parser."""

from typing import Any, ClassVar, Dict, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from ..base import BaseParser


class OpenVASVulnParser(BaseParser):
    """Parse OpenVAS/Greenbone CSV exports into ParsedVulnerability."""

    name: ClassVar[str] = "openvas_vuln"
    source: ClassVar[str] = "openvas"
    data_type: ClassVar[str] = "vulnerability"
    description: ClassVar[str] = "OpenVAS/Greenbone vulnerability CSV export"

    DETECTION_COLUMNS: ClassVar[Tuple[str, ...]] = (
        "NVT OID",
        "Threat",
        "Host",
        "NVT Name",
        "Solution Type",
    )

    COLUMN_MAPPING: ClassVar[Dict[str, str]] = {
        "NVT OID": "scanner_id",
        "CVEs": "cve_id",
        "NVT Name": "title",
        "Threat": "severity",
        "CVSS": "cvss_score",
        "Summary": "description",
        "Specific Result": "solution",
        "Hostname": "hostname",
        "Host": "ip_address",
        "Port": "port",
        "Protocol": "protocol",
    }

    def _parse_row(self, row: Dict[str, Any]) -> ParsedVulnerability:
        mapped = dict(row)
        extra = mapped.pop("extra", {})

        mapped["severity"] = normalize_severity(mapped.get("severity"), "openvas")

        cvss = mapped.get("cvss_score")
        mapped["cvss_score"] = float(cvss) if cvss else None

        # OpenVAS port field is "port/protocol" format
        port_raw = mapped.get("port")
        if port_raw and "/" in str(port_raw):
            parts = str(port_raw).split("/", 1)
            try:
                mapped["port"] = int(parts[0])
            except ValueError:
                mapped["port"] = None
            mapped.setdefault("protocol", parts[1])
        elif port_raw:
            try:
                mapped["port"] = int(port_raw)
            except ValueError:
                mapped["port"] = None
        else:
            mapped["port"] = None

        if not mapped.get("title"):
            mapped["title"] = f"NVT-{mapped.get('scanner_id', 'unknown')}"

        mapped["extra"] = extra
        return ParsedVulnerability(**mapped)
