"""Tests for Pydantic data models."""

import pytest
from pydantic import ValidationError

from secimport.models import (
    ParsedAsset,
    ParsedEndpoint,
    ParsedGroup,
    ParsedNetworkObservation,
    ParsedOwnerMapping,
    ParsedUser,
    ParsedVulnerability,
    ParseResult,
    SourceMetadata,
)


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


class TestSourceMetadata:
    def test_defaults(self):
        meta = SourceMetadata()
        assert meta.source_system is None
        assert meta.source_instance is None
        assert meta.ingested_at is not None
        assert meta.record_id is None

    def test_custom(self):
        meta = SourceMetadata(source_system="crowdstrike", record_id="abc-123")
        assert meta.source_system == "crowdstrike"
        assert meta.record_id == "abc-123"

    def test_inherited_by_vuln(self):
        vuln = ParsedVulnerability(
            title="Test", severity="High", source_system="nessus"
        )
        assert vuln.source_system == "nessus"
        assert vuln.ingested_at is not None

    def test_inherited_by_asset(self):
        asset = ParsedAsset(hostname="srv01", source_system="cmdb")
        assert asset.source_system == "cmdb"


class TestParsedEndpoint:
    def test_minimal(self):
        ep = ParsedEndpoint(hostname="ws01")
        assert ep.hostname == "ws01"
        assert ep.agent_status is None
        assert ep.tags == []

    def test_full(self):
        ep = ParsedEndpoint(
            hostname="ws01.example.com",
            ip_address="10.0.1.5",
            mac_address="AA:BB:CC:DD:EE:FF",
            agent_id="falcon-001",
            agent_version="7.10.0",
            agent_status="Online",
            operating_system="Windows",
            os_version="11",
            policy_name="Default",
            policy_status="Compliant",
            isolation_status="Normal",
            prevention_mode="Prevent",
            endpoint_type="Workstation",
            site_name="HQ",
            tags=["vip", "finance"],
            owner_email="user@example.com",
            source_system="crowdstrike",
        )
        assert ep.agent_id == "falcon-001"
        assert ep.policy_status == "Compliant"
        assert len(ep.tags) == 2
        assert ep.source_system == "crowdstrike"


class TestParsedUser:
    def test_minimal(self):
        user = ParsedUser(username="jdoe")
        assert user.username == "jdoe"
        assert user.groups == []

    def test_full(self):
        user = ParsedUser(
            username="jdoe",
            email="jdoe@example.com",
            display_name="Jane Doe",
            employee_id="E12345",
            enabled=True,
            department="Engineering",
            title="Senior Engineer",
            manager_email="boss@example.com",
            groups=["CN=Dev,DC=example", "CN=All,DC=example"],
            source_system="active_directory",
        )
        assert user.enabled is True
        assert len(user.groups) == 2
        assert user.source_system == "active_directory"


class TestParsedGroup:
    def test_minimal(self):
        group = ParsedGroup(name="Admins")
        assert group.name == "Admins"
        assert group.members == []
        assert group.member_count is None

    def test_full(self):
        group = ParsedGroup(
            name="SecurityTeam",
            display_name="Security Team",
            description="Security operations group",
            group_type="Security",
            member_count=3,
            members=["alice@example.com", "bob@example.com", "carol@example.com"],
            source_system="azure_ad",
        )
        assert group.group_type == "Security"
        assert group.member_count == 3


class TestParsedNetworkObservation:
    def test_minimal(self):
        obs = ParsedNetworkObservation(ip_address="10.0.0.1")
        assert obs.ip_address == "10.0.0.1"
        assert obs.tags == []

    def test_full(self):
        obs = ParsedNetworkObservation(
            ip_address="10.0.0.1",
            mac_address="AA:BB:CC:DD:EE:FF",
            hostname="printer01",
            vlan="VLAN100",
            subnet="10.0.0.0/24",
            device_type_guess="Printer",
            risk_score=25.0,
            tags=["iot"],
            source_system="darktrace",
        )
        assert obs.device_type_guess == "Printer"
        assert obs.risk_score == 25.0

    def test_risk_score_range(self):
        with pytest.raises(ValidationError):
            ParsedNetworkObservation(risk_score=101.0)


class TestParseResult:
    def test_minimal(self):
        result = ParseResult(source_type="qualys", data_type="vulnerability")
        assert result.total_rows == 0
        assert result.errors == []

    def test_enhanced_fields(self):
        result = ParseResult(
            source_type="nessus",
            data_type="vulnerability",
            skipped_count=5,
            duration_seconds=1.23,
            parser_name="NessusParser",
        )
        assert result.skipped_count == 5
        assert result.duration_seconds == 1.23
        assert result.parser_name == "NessusParser"
