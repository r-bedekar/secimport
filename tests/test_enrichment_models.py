"""Tests for enrichment data models."""

from secimport.enrichment.models import (
    CorrelationKey,
    EnrichedAsset,
    FieldProvenance,
    GapReport,
    MatchResult,
)


class TestFieldProvenance:
    def test_basic(self):
        fp = FieldProvenance(value="10.0.0.1", source_system="qualys")
        assert fp.value == "10.0.0.1"
        assert fp.confidence == 1.0

    def test_custom_confidence(self):
        fp = FieldProvenance(value="host01", source_system="ndr", confidence=0.6)
        assert fp.confidence == 0.6


class TestCorrelationKey:
    def test_empty(self):
        key = CorrelationKey()
        assert key.is_empty()

    def test_not_empty(self):
        key = CorrelationKey(hostnames={"web01"})
        assert not key.is_empty()

    def test_overlaps_hostname(self):
        a = CorrelationKey(hostnames={"web01"}, ip_addresses={"10.0.0.1"})
        b = CorrelationKey(hostnames={"web01"}, ip_addresses={"10.0.0.2"})
        assert a.overlaps(b)

    def test_no_overlap(self):
        a = CorrelationKey(hostnames={"web01"})
        b = CorrelationKey(hostnames={"web02"})
        assert not a.overlaps(b)

    def test_overlaps_agent_id(self):
        a = CorrelationKey(agent_ids={"falcon-001"})
        b = CorrelationKey(agent_ids={"falcon-001"}, hostnames={"other"})
        assert a.overlaps(b)

    def test_merge(self):
        a = CorrelationKey(hostnames={"web01"}, ip_addresses={"10.0.0.1"})
        b = CorrelationKey(hostnames={"web01.local"}, mac_addresses={"aa:bb:cc:dd:ee:ff"})
        a.merge(b)
        assert "web01" in a.hostnames
        assert "web01.local" in a.hostnames
        assert "aa:bb:cc:dd:ee:ff" in a.mac_addresses
        assert "10.0.0.1" in a.ip_addresses


class TestMatchResult:
    def test_no_match(self):
        mr = MatchResult()
        assert mr.matched is False
        assert mr.confidence == 0.0

    def test_match(self):
        mr = MatchResult(matched=True, confidence=0.85, matched_on=["hostname"])
        assert mr.matched
        assert mr.confidence == 0.85


class TestEnrichedAsset:
    def test_set_field_new(self):
        asset = EnrichedAsset()
        asset.set_field("hostname", "web01", "qualys", confidence=0.8)
        assert asset.hostname is not None
        assert asset.hostname.value == "web01"
        assert asset.hostname.confidence == 0.8

    def test_set_field_higher_confidence_wins(self):
        asset = EnrichedAsset()
        asset.set_field("hostname", "web01", "qualys", confidence=0.8)
        asset.set_field("hostname", "WEB01.local", "crowdstrike", confidence=0.95)
        assert asset.hostname.value == "WEB01.local"
        assert asset.hostname.source_system == "crowdstrike"

    def test_set_field_lower_confidence_ignored(self):
        asset = EnrichedAsset()
        asset.set_field("hostname", "web01", "crowdstrike", confidence=0.95)
        asset.set_field("hostname", "web-01", "siem", confidence=0.5)
        assert asset.hostname.value == "web01"

    def test_set_field_none_value_ignored(self):
        asset = EnrichedAsset()
        asset.set_field("hostname", None, "qualys", confidence=1.0)
        assert asset.hostname is None


class TestGapReport:
    def test_basic(self):
        report = GapReport(
            source_a="crowdstrike",
            source_b="qualys",
            in_a_not_b=[CorrelationKey(hostnames={"host1"})],
            in_b_not_a=[
                CorrelationKey(hostnames={"host2"}),
                CorrelationKey(hostnames={"host3"}),
            ],
            in_both=[CorrelationKey(hostnames={"host4"})],
        )
        assert report.total_a == 2  # 1 in_a_not_b + 1 in_both
        assert report.total_b == 3  # 2 in_b_not_a + 1 in_both
        assert report.coverage_a_to_b == 0.5  # 1/2
        assert abs(report.coverage_b_to_a - 1 / 3) < 1e-9

    def test_empty(self):
        report = GapReport(source_a="a", source_b="b")
        assert report.total_a == 0
        assert report.coverage_a_to_b == 0.0
