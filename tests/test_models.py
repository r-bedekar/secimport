"""Tests for Pydantic data models."""

import pytest
from pydantic import ValidationError

from secimport.models import ParsedAsset, ParsedOwnerMapping, ParsedVulnerability, ParseResult


class TestParsedVulnerability:
    def test_minimal(self):
        vuln = ParsedVulnerability(title="Test Vuln", severity="High")
        assert vuln.title == "Test Vuln"
        assert vuln.severity == "High"
        assert vuln.extra == {}

    def test_full(self):
        vuln = ParsedVulnerability(
            scanner_id="12345",
            cve_id="CVE-2024-0001",
            title="SQL Injection",
            severity="Critical",
            cvss_score=9.8,
            description="A SQL injection vulnerability",
            solution="Patch to latest version",
            hostname="web01.example.com",
            ip_address="10.0.0.1",
            port=443,
            protocol="tcp",
            extra={"raw_id": "abc"},
        )
        assert vuln.cvss_score == 9.8
        assert vuln.cve_id == "CVE-2024-0001"

    def test_cvss_range(self):
        with pytest.raises(ValidationError):
            ParsedVulnerability(title="Bad", severity="High", cvss_score=11.0)

    def test_title_required(self):
        with pytest.raises(ValidationError):
            ParsedVulnerability(severity="High")


class TestParsedAsset:
    def test_minimal(self):
        asset = ParsedAsset(hostname="server01")
        assert asset.hostname == "server01"
        assert asset.extra == {}

    def test_full(self):
        asset = ParsedAsset(
            hostname="server01",
            ip_address="10.0.0.5",
            asset_type="Server",
            environment="Production",
            criticality="High",
            owner_email="admin@example.com",
            operating_system="Ubuntu",
            os_version="22.04",
        )
        assert asset.environment == "Production"


class TestParsedOwnerMapping:
    def test_defaults(self):
        mapping = ParsedOwnerMapping(ip_range="10.0.0.0/24", owner_email="ops@example.com")
        assert mapping.confidence == 1.0

    def test_confidence_range(self):
        with pytest.raises(ValidationError):
            ParsedOwnerMapping(confidence=1.5)


class TestParseResult:
    def test_minimal(self):
        result = ParseResult(source_type="qualys", data_type="vulnerability")
        assert result.total_rows == 0
        assert result.errors == []
