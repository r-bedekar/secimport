"""Tests for asset correlator and gap analysis."""

from secimport.enrichment.correlator import AssetCorrelator
from secimport.models.base import (
    ParsedAsset,
    ParsedEndpoint,
    ParsedNetworkObservation,
    ParsedOwnerMapping,
    ParsedVulnerability,
)


def _iter(*items):
    """Helper to make an iterator from items."""
    return iter(items)


class TestAssetCorrelatorBasic:
    def test_empty(self):
        c = AssetCorrelator()
        assert c.asset_count == 0
        assert list(c.get_enriched_assets()) == []

    def test_ingest_single_asset(self):
        c = AssetCorrelator()
        count = c.ingest_assets(
            _iter(ParsedAsset(hostname="web01", ip_address="10.0.0.1", source_system="qualys"))
        )
        assert count == 1
        assert c.asset_count == 1

        enriched = list(c.get_enriched_assets())[0]
        assert enriched.hostname.value == "web01"
        assert enriched.ip_address.value == "10.0.0.1"
        assert "qualys" in enriched.present_in_sources

    def test_ingest_single_endpoint(self):
        c = AssetCorrelator()
        count = c.ingest_endpoints(
            _iter(
                ParsedEndpoint(
                    hostname="ws01",
                    agent_id="falcon-001",
                    agent_status="Online",
                    source_system="crowdstrike",
                )
            )
        )
        assert count == 1
        assert c.asset_count == 1

        enriched = list(c.get_enriched_assets())[0]
        assert enriched.agent_id.value == "falcon-001"
        assert enriched.agent_status.value == "Online"


class TestCorrelationMatching:
    def test_same_hostname_correlates(self):
        c = AssetCorrelator()
        c.ingest_assets(
            _iter(ParsedAsset(hostname="web01", ip_address="10.0.0.1", source_system="qualys"))
        )
        c.ingest_endpoints(
            _iter(
                ParsedEndpoint(
                    hostname="web01",
                    agent_id="falcon-001",
                    agent_status="Online",
                    source_system="crowdstrike",
                )
            )
        )
        assert c.asset_count == 1  # Merged into one

        enriched = list(c.get_enriched_assets())[0]
        assert "qualys" in enriched.present_in_sources
        assert "crowdstrike" in enriched.present_in_sources
        # EDR has higher confidence, so agent fields are set
        assert enriched.agent_id.value == "falcon-001"
        # Hostname from crowdstrike (0.95) should win over qualys (0.80)
        assert enriched.hostname.source_system == "crowdstrike"

    def test_same_ip_correlates(self):
        c = AssetCorrelator()
        c.ingest_assets(
            _iter(ParsedAsset(ip_address="10.0.0.5", source_system="qualys"))
        )
        c.ingest_endpoints(
            _iter(ParsedEndpoint(ip_address="10.0.0.5", source_system="crowdstrike"))
        )
        assert c.asset_count == 1

    def test_different_assets_not_merged(self):
        c = AssetCorrelator()
        c.ingest_assets(
            _iter(
                ParsedAsset(hostname="web01", source_system="qualys"),
                ParsedAsset(hostname="web02", source_system="qualys"),
            )
        )
        assert c.asset_count == 2


class TestMultiSourceCorrelation:
    def test_three_sources(self):
        """Simulate scanner + EDR + NDR all seeing the same host."""
        c = AssetCorrelator()

        # Scanner finds it
        c.ingest_assets(
            _iter(
                ParsedAsset(
                    hostname="db01",
                    ip_address="10.0.1.10",
                    operating_system="Ubuntu",
                    source_system="qualys",
                )
            )
        )

        # EDR agent installed on it
        c.ingest_endpoints(
            _iter(
                ParsedEndpoint(
                    hostname="db01",
                    ip_address="10.0.1.10",
                    mac_address="AA:BB:CC:DD:EE:01",
                    agent_id="s1-agent-999",
                    agent_status="Online",
                    policy_status="Compliant",
                    operating_system="Ubuntu 22.04",
                    source_system="sentinelone",
                )
            )
        )

        # NDR observes it passively
        c.ingest_network_observations(
            _iter(
                ParsedNetworkObservation(
                    ip_address="10.0.1.10",
                    mac_address="AA:BB:CC:DD:EE:01",
                    device_type_guess="Server",
                    source_system="darktrace",
                )
            )
        )

        assert c.asset_count == 1  # All three correlated

        enriched = list(c.get_enriched_assets())[0]
        assert len(enriched.present_in_sources) == 3
        assert "qualys" in enriched.present_in_sources
        assert "sentinelone" in enriched.present_in_sources
        assert "darktrace" in enriched.present_in_sources

        # EDR has highest confidence (0.95) for hostname/OS
        assert enriched.hostname.source_system == "sentinelone"
        assert enriched.operating_system.source_system == "sentinelone"
        assert enriched.operating_system.value == "Ubuntu 22.04"


class TestVulnerabilityIngestion:
    def test_vuln_counts(self):
        c = AssetCorrelator()
        c.ingest_assets(
            _iter(ParsedAsset(hostname="web01", ip_address="10.0.0.1", source_system="qualys"))
        )
        c.ingest_vulnerabilities(
            _iter(
                ParsedVulnerability(
                    title="SQLi", severity="Critical",
                    hostname="web01", source_system="qualys",
                ),
                ParsedVulnerability(
                    title="XSS", severity="High",
                    hostname="web01", source_system="qualys",
                ),
                ParsedVulnerability(
                    title="Info Leak", severity="Medium",
                    hostname="web01", source_system="qualys",
                ),
            )
        )

        enriched = list(c.get_enriched_assets())[0]
        assert enriched.vulnerability_count == 3
        assert enriched.critical_vuln_count == 1
        assert enriched.high_vuln_count == 1


class TestOwnerMappings:
    def test_owner_applied(self):
        c = AssetCorrelator()
        c.ingest_assets(
            _iter(ParsedAsset(ip_address="10.0.0.1", source_system="qualys"))
        )
        c.ingest_owner_mappings(
            _iter(
                ParsedOwnerMapping(
                    ip_address="10.0.0.1",
                    owner_email="admin@example.com",
                    department="IT",
                    source_system="infoblox",
                    confidence=0.9,
                )
            )
        )

        enriched = list(c.get_enriched_assets())[0]
        assert enriched.owner_email.value == "admin@example.com"


class TestGapAnalysis:
    def test_gap_report(self):
        c = AssetCorrelator()
        c.ingest_assets(
            _iter(
                ParsedAsset(hostname="web01", source_system="qualys"),
                ParsedAsset(hostname="web02", source_system="qualys"),
                ParsedAsset(hostname="web03", source_system="qualys"),
            )
        )
        c.ingest_endpoints(
            _iter(
                ParsedEndpoint(hostname="web01", source_system="crowdstrike"),
                ParsedEndpoint(hostname="web04", source_system="crowdstrike"),
            )
        )

        gap = c.gap_analysis("qualys", "crowdstrike")
        assert len(gap.in_both) == 1  # web01
        assert len(gap.in_a_not_b) == 2  # web02, web03
        assert len(gap.in_b_not_a) == 1  # web04
        assert gap.total_a == 3
        assert gap.total_b == 2
        assert gap.coverage_a_to_b == 1 / 3

    def test_full_coverage(self):
        c = AssetCorrelator()
        c.ingest_assets(
            _iter(ParsedAsset(hostname="srv01", source_system="qualys"))
        )
        c.ingest_endpoints(
            _iter(ParsedEndpoint(hostname="srv01", source_system="crowdstrike"))
        )

        gap = c.gap_analysis("qualys", "crowdstrike")
        assert gap.coverage_a_to_b == 1.0
        assert gap.coverage_b_to_a == 1.0


class TestDeduplication:
    def test_deduplicate_merges(self):
        c = AssetCorrelator()
        # Ingest two assets that initially don't match but share a MAC
        c.ingest_assets(
            _iter(
                ParsedAsset(hostname="web01", source_system="qualys"),
                ParsedAsset(hostname="web02", source_system="nessus"),
            )
        )
        assert c.asset_count == 2

        # Now add an endpoint linking them via MAC
        c.ingest_endpoints(
            _iter(
                ParsedEndpoint(
                    hostname="web01",
                    mac_address="AA:BB:CC:DD:EE:FF",
                    source_system="crowdstrike",
                ),
            )
        )
        # web01 now has MAC; add another endpoint for web02 with same MAC
        c.ingest_endpoints(
            _iter(
                ParsedEndpoint(
                    hostname="web02",
                    mac_address="AA:BB:CC:DD:EE:FF",
                    source_system="sentinelone",
                ),
            )
        )

        merges = c.deduplicate()
        assert merges >= 1
        assert c.asset_count < 4  # Should have merged some
