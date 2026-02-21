"""Tests for file parsers and auto-detection."""

import csv
import tempfile
from pathlib import Path

import pytest

from secimport.detectors import (
    detect_all,
    detect_data_type,
    detect_parser,
    detect_source,
    parse_file,
)
from secimport.models.base import (
    ParsedAsset,
    ParsedOwnerMapping,
    ParsedVulnerability,
)
from secimport.parsers.base import BaseParser, ParserRegistry

# ---------------------------------------------------------------------------
# Fixtures: temp CSV files
# ---------------------------------------------------------------------------


def _write_csv(headers: list[str], rows: list[list[str]]) -> Path:
    """Write a temp CSV and return its path."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False, newline=""
    )
    writer = csv.writer(tmp)
    writer.writerow(headers)
    writer.writerows(rows)
    tmp.flush()
    return Path(tmp.name)


@pytest.fixture()
def qualys_csv() -> Path:
    headers = [
        "QID", "CVE ID", "Title", "Severity",
        "CVSS Base", "DNS", "IP", "Port", "Protocol", "Vuln Status",
    ]
    rows = [
        ["12345", "CVE-2023-1234", "Test Vuln", "5",
         "9.8", "host1.example.com", "10.0.0.1", "443", "tcp", "Active"],
        ["67890", "", "Another Vuln", "3",
         "5.5", "host2.example.com", "10.0.0.2", "80", "tcp", "Active"],
    ]
    return _write_csv(headers, rows)


@pytest.fixture()
def nessus_csv() -> Path:
    headers = [
        "Plugin ID", "CVE", "Name", "Risk",
        "CVSS v3.0 Base Score", "Host", "IP Address",
        "Port", "Protocol", "Synopsis",
    ]
    rows = [
        ["10001", "CVE-2023-5678", "Nessus Vuln", "Critical",
         "9.1", "host1", "192.168.1.1", "22", "tcp", "A test"],
    ]
    return _write_csv(headers, rows)


@pytest.fixture()
def tenable_csv() -> Path:
    headers = [
        "Plugin ID", "Severity", "Asset UUID",
        "Plugin Name", "Plugin Family", "CVE", "IP Address", "Port",
    ]
    rows = [
        ["20001", "High", "uuid-123", "Tenable Finding",
         "Web Servers", "CVE-2024-0001", "10.1.1.1", "8080"],
    ]
    return _write_csv(headers, rows)


@pytest.fixture()
def rapid7_csv() -> Path:
    headers = [
        "Vulnerability ID", "Risk Score", "Asset IP Address",
        "Vulnerability Title", "Exploits", "Severity", "CVSS Score",
    ]
    rows = [
        ["vuln-001", "850", "10.2.2.2",
         "Rapid7 Finding", "1", "Severe", "8.5"],
    ]
    return _write_csv(headers, rows)


@pytest.fixture()
def crowdstrike_csv() -> Path:
    headers = [
        "Vulnerability ID", "CVE", "Severity", "Hostname",
        "Aid", "Vulnerability Name", "CVSS Score",
    ]
    rows = [
        ["CS-001", "CVE-2024-9999", "Critical",
         "cs-host1", "aid-123", "CS Finding", "10.0"],
    ]
    return _write_csv(headers, rows)


@pytest.fixture()
def openvas_csv() -> Path:
    headers = [
        "NVT OID", "Threat", "Host", "NVT Name",
        "Solution Type", "CVEs", "CVSS", "Port",
    ]
    rows = [
        ["1.3.6.1.4.1.123", "High", "10.3.3.3",
         "OpenVAS Finding", "VendorFix", "CVE-2024-0002", "7.5", "443/tcp"],
    ]
    return _write_csv(headers, rows)


@pytest.fixture()
def asset_csv() -> Path:
    headers = [
        "Hostname", "IP Address", "Asset Type",
        "Owner", "Department", "Environment", "OS",
    ]
    rows = [
        ["srv-01", "10.0.0.10", "Server",
         "admin@example.com", "IT", "Production", "Ubuntu 22.04"],
        ["ws-01", "10.0.0.20", "Workstation",
         "user@example.com", "HR", "Development", "Windows 11"],
    ]
    return _write_csv(headers, rows)


@pytest.fixture()
def servicenow_csv() -> Path:
    headers = [
        "sys_id", "name", "sys_class_name",
        "assigned_to", "u_environment", "ip_address", "os",
    ]
    rows = [
        ["abc123", "sn-host1", "cmdb_ci_server",
         "John Doe", "Production", "10.5.5.5", "Linux"],
    ]
    return _write_csv(headers, rows)


@pytest.fixture()
def owner_csv() -> Path:
    headers = [
        "IP Address", "Owner", "Department",
        "Subnet", "Business Unit", "Location",
    ]
    rows = [
        ["10.0.0.0/24", "netops@example.com", "Network Ops",
         "10.0.0.0/24", "Infrastructure", "DC1"],
    ]
    return _write_csv(headers, rows)


@pytest.fixture()
def ipam_csv() -> Path:
    headers = [
        "Network", "Network View", "Comment",
        "EA-Site", "EA-Department", "EA-Owner",
    ]
    rows = [
        ["10.10.0.0/16", "default", "Office Network",
         "NYC", "Engineering", "eng@example.com"],
    ]
    return _write_csv(headers, rows)


# ---------------------------------------------------------------------------
# ParserRegistry tests
# ---------------------------------------------------------------------------


class TestParserRegistry:
    def test_all_parsers_registered(self) -> None:
        parsers = ParserRegistry.list_parsers()
        assert len(parsers) == 11

    def test_by_data_type_vulnerability(self) -> None:
        vuln = ParserRegistry.by_data_type("vulnerability")
        assert len(vuln) == 7
        assert "qualys_vuln" in vuln

    def test_by_data_type_asset(self) -> None:
        assets = ParserRegistry.by_data_type("asset")
        assert len(assets) == 2
        assert "generic_asset" in assets

    def test_by_data_type_owner(self) -> None:
        owners = ParserRegistry.by_data_type("owner")
        assert len(owners) == 2
        assert "generic_owner" in owners

    def test_get_by_name(self) -> None:
        cls = ParserRegistry.get("qualys_vuln")
        assert cls is not None
        assert cls.source == "qualys"

    def test_get_unknown_returns_none(self) -> None:
        assert ParserRegistry.get("nonexistent") is None


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------


class TestDetection:
    def test_detect_qualys_columns(self) -> None:
        columns = [
            "QID", "CVE ID", "Title", "Severity",
            "IP", "DNS", "Vuln Status",
        ]
        from secimport.parsers.vulnerabilities.qualys import (
            QualysVulnParser,
        )

        score = QualysVulnParser.detect(columns)
        assert score == 1.0

    def test_detect_nessus_columns(self) -> None:
        columns = ["Plugin ID", "Risk", "Host", "Name", "Synopsis"]
        from secimport.parsers.vulnerabilities.nessus import (
            NessusVulnParser,
        )

        score = NessusVulnParser.detect(columns)
        assert score == 1.0

    def test_detect_no_match(self) -> None:
        columns = ["foo", "bar", "baz"]
        from secimport.parsers.vulnerabilities.qualys import (
            QualysVulnParser,
        )

        score = QualysVulnParser.detect(columns)
        assert score == 0.0

    def test_detect_partial_match(self) -> None:
        columns = ["QID", "Title", "Extra"]
        from secimport.parsers.vulnerabilities.qualys import (
            QualysVulnParser,
        )

        score = QualysVulnParser.detect(columns)
        assert 0 < score < 1.0

    def test_detect_case_insensitive(self) -> None:
        columns = [
            "qid", "severity", "ip", "dns", "title", "vuln status",
        ]
        from secimport.parsers.vulnerabilities.qualys import (
            QualysVulnParser,
        )

        score = QualysVulnParser.detect(columns)
        assert score == 1.0

    def test_detect_parser_qualys_file(self, qualys_csv: Path) -> None:
        parser_cls = detect_parser(qualys_csv)
        assert parser_cls is not None
        assert parser_cls.source == "qualys"

    def test_detect_parser_nessus_file(self, nessus_csv: Path) -> None:
        parser_cls = detect_parser(nessus_csv)
        assert parser_cls is not None
        assert parser_cls.source == "nessus"

    def test_detect_parser_tenable_file(self, tenable_csv: Path) -> None:
        parser_cls = detect_parser(tenable_csv)
        assert parser_cls is not None
        assert parser_cls.source == "tenable"

    def test_detect_parser_rapid7_file(self, rapid7_csv: Path) -> None:
        parser_cls = detect_parser(rapid7_csv)
        assert parser_cls is not None
        assert parser_cls.source == "rapid7"

    def test_detect_source(self, qualys_csv: Path) -> None:
        assert detect_source(qualys_csv) == "qualys"

    def test_detect_data_type(self, qualys_csv: Path) -> None:
        assert detect_data_type(qualys_csv) == "vulnerability"

    def test_detect_all_returns_sorted(self, qualys_csv: Path) -> None:
        results = detect_all(qualys_csv)
        assert len(results) > 0
        scores = [score for _, score in results]
        assert scores == sorted(scores, reverse=True)

    def test_detect_parser_with_data_type_filter(
        self, asset_csv: Path
    ) -> None:
        parser_cls = detect_parser(asset_csv, data_type="asset")
        assert parser_cls is not None
        assert parser_cls.data_type == "asset"


# ---------------------------------------------------------------------------
# Parsing tests (vulnerability parsers)
# ---------------------------------------------------------------------------


class TestQualysParser:
    def test_parse(self, qualys_csv: Path) -> None:
        from secimport.parsers.vulnerabilities.qualys import (
            QualysVulnParser,
        )

        parser = QualysVulnParser()
        results = list(parser.parse(qualys_csv))
        assert len(results) == 2
        assert all(isinstance(r, ParsedVulnerability) for r in results)

    def test_parse_fields(self, qualys_csv: Path) -> None:
        from secimport.parsers.vulnerabilities.qualys import (
            QualysVulnParser,
        )

        parser = QualysVulnParser()
        vuln = list(parser.parse(qualys_csv))[0]
        assert vuln.scanner_id == "12345"
        assert vuln.cve_id == "CVE-2023-1234"
        assert vuln.title == "Test Vuln"
        assert vuln.severity == "Critical"  # Qualys 5 -> Critical
        assert vuln.cvss_score == 9.8
        assert vuln.hostname == "host1.example.com"
        assert vuln.ip_address == "10.0.0.1"
        assert vuln.port == 443

    def test_severity_normalization(self, qualys_csv: Path) -> None:
        from secimport.parsers.vulnerabilities.qualys import (
            QualysVulnParser,
        )

        parser = QualysVulnParser()
        results = list(parser.parse(qualys_csv))
        assert results[0].severity == "Critical"  # 5
        assert results[1].severity == "Medium"  # 3


class TestNessusParser:
    def test_parse(self, nessus_csv: Path) -> None:
        from secimport.parsers.vulnerabilities.nessus import (
            NessusVulnParser,
        )

        parser = NessusVulnParser()
        results = list(parser.parse(nessus_csv))
        assert len(results) == 1
        vuln = results[0]
        assert vuln.scanner_id == "10001"
        assert vuln.severity == "Critical"
        assert vuln.cvss_score == 9.1


class TestTenableParser:
    def test_parse(self, tenable_csv: Path) -> None:
        from secimport.parsers.vulnerabilities.tenable import (
            TenableVulnParser,
        )

        parser = TenableVulnParser()
        results = list(parser.parse(tenable_csv))
        assert len(results) == 1
        assert results[0].severity == "High"


class TestRapid7Parser:
    def test_parse(self, rapid7_csv: Path) -> None:
        from secimport.parsers.vulnerabilities.rapid7 import (
            Rapid7VulnParser,
        )

        parser = Rapid7VulnParser()
        results = list(parser.parse(rapid7_csv))
        assert len(results) == 1
        assert results[0].severity == "Critical"  # Severe -> Critical
        assert results[0].cvss_score == 8.5


class TestCrowdStrikeParser:
    def test_parse(self, crowdstrike_csv: Path) -> None:
        from secimport.parsers.vulnerabilities.crowdstrike import (
            CrowdStrikeVulnParser,
        )

        parser = CrowdStrikeVulnParser()
        results = list(parser.parse(crowdstrike_csv))
        assert len(results) == 1
        assert results[0].severity == "Critical"
        assert results[0].cvss_score == 10.0


class TestOpenVASParser:
    def test_parse(self, openvas_csv: Path) -> None:
        from secimport.parsers.vulnerabilities.openvas import (
            OpenVASVulnParser,
        )

        parser = OpenVASVulnParser()
        results = list(parser.parse(openvas_csv))
        assert len(results) == 1
        vuln = results[0]
        assert vuln.severity == "Critical"  # OpenVAS High -> Critical
        assert vuln.port == 443
        assert vuln.protocol == "tcp"


# ---------------------------------------------------------------------------
# Parsing tests (asset parsers)
# ---------------------------------------------------------------------------


class TestGenericAssetParser:
    def test_parse(self, asset_csv: Path) -> None:
        from secimport.parsers.assets.csv_generic import (
            GenericAssetParser,
        )

        parser = GenericAssetParser()
        results = list(parser.parse(asset_csv))
        assert len(results) == 2
        assert all(isinstance(r, ParsedAsset) for r in results)

    def test_parse_fields(self, asset_csv: Path) -> None:
        from secimport.parsers.assets.csv_generic import (
            GenericAssetParser,
        )

        parser = GenericAssetParser()
        asset = list(parser.parse(asset_csv))[0]
        assert asset.hostname == "srv-01"
        assert asset.ip_address == "10.0.0.10"
        assert asset.asset_type == "Server"
        assert asset.owner_email == "admin@example.com"
        assert asset.department == "IT"
        assert asset.environment == "Production"


class TestServiceNowAssetParser:
    def test_parse(self, servicenow_csv: Path) -> None:
        from secimport.parsers.assets.servicenow import (
            ServiceNowAssetParser,
        )

        parser = ServiceNowAssetParser()
        results = list(parser.parse(servicenow_csv))
        assert len(results) == 1
        asset = results[0]
        assert asset.hostname == "sn-host1"
        assert asset.asset_type == "cmdb_ci_server"


# ---------------------------------------------------------------------------
# Parsing tests (owner parsers)
# ---------------------------------------------------------------------------


class TestGenericOwnerParser:
    def test_parse(self, owner_csv: Path) -> None:
        from secimport.parsers.owners.csv_generic import (
            GenericOwnerParser,
        )

        parser = GenericOwnerParser()
        results = list(parser.parse(owner_csv))
        assert len(results) == 1
        assert isinstance(results[0], ParsedOwnerMapping)

    def test_parse_fields(self, owner_csv: Path) -> None:
        from secimport.parsers.owners.csv_generic import (
            GenericOwnerParser,
        )

        parser = GenericOwnerParser()
        owner = list(parser.parse(owner_csv))[0]
        assert owner.owner_email == "netops@example.com"
        assert owner.department == "Network Ops"
        assert owner.subnet == "10.0.0.0/24"


class TestIPAMOwnerParser:
    def test_parse(self, ipam_csv: Path) -> None:
        from secimport.parsers.owners.ipam import IPAMOwnerParser

        parser = IPAMOwnerParser()
        results = list(parser.parse(ipam_csv))
        assert len(results) == 1
        owner = results[0]
        assert owner.owner_email == "eng@example.com"
        assert owner.department == "Engineering"
        assert owner.location == "NYC"
        assert owner.confidence == 0.8  # IPAM default


# ---------------------------------------------------------------------------
# parse_file() integration tests
# ---------------------------------------------------------------------------


class TestParseFile:
    def test_parse_file_auto_detect(self, qualys_csv: Path) -> None:
        data_iter, result = parse_file(qualys_csv)
        items = list(data_iter)
        assert len(items) == 2
        assert result.source_type == "qualys"
        assert result.data_type == "vulnerability"
        assert result.parsed_count == 2

    def test_parse_file_explicit_parser(
        self, qualys_csv: Path
    ) -> None:
        data_iter, result = parse_file(
            qualys_csv, parser_name="qualys_vuln"
        )
        items = list(data_iter)
        assert len(items) == 2
        assert result.source_type == "qualys"

    def test_parse_file_unknown_parser_raises(
        self, qualys_csv: Path
    ) -> None:
        with pytest.raises(ValueError, match="Unknown parser"):
            parse_file(qualys_csv, parser_name="nonexistent")

    def test_parse_file_no_match_raises(self) -> None:
        csv_path = _write_csv(
            ["foo", "bar", "baz"], [["a", "b", "c"]]
        )
        with pytest.raises(ValueError, match="Could not detect"):
            parse_file(csv_path)


# ---------------------------------------------------------------------------
# BaseParser.read_file / get_columns tests
# ---------------------------------------------------------------------------


class TestBaseParserIO:
    def test_get_columns(self, qualys_csv: Path) -> None:
        columns = BaseParser.get_columns(qualys_csv)
        assert "QID" in columns
        assert "Severity" in columns

    def test_read_file(self, qualys_csv: Path) -> None:
        df = BaseParser.read_file(qualys_csv)
        assert len(df) == 2
        assert "QID" in df.columns

    def test_column_mapping(self) -> None:
        from secimport.parsers.vulnerabilities.qualys import (
            QualysVulnParser,
        )

        parser = QualysVulnParser()
        row = {
            "QID": "123", "Title": "Test",
            "Severity": "5", "IP": "1.1.1.1", "Extra Col": "val",
        }
        mapped = parser._map_columns(row)
        assert mapped["scanner_id"] == "123"
        assert mapped["title"] == "Test"
        assert mapped["ip_address"] == "1.1.1.1"
        assert "Extra Col" in mapped["extra"]
