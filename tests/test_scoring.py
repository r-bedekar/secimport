"""Tests for confidence scoring module."""

from secimport.enrichment.scoring import MatchWeights, SourceConfidence


class TestMatchWeights:
    def test_agent_id_highest(self):
        assert MatchWeights.get("agent_id") == 0.99

    def test_ip_lowest(self):
        assert MatchWeights.get("ip_address") == 0.70

    def test_unknown_default(self):
        assert MatchWeights.get("unknown_field") == 0.5

    def test_ordering(self):
        weights = MatchWeights.WEIGHTS
        assert weights["agent_id"] > weights["serial_number"]
        assert weights["serial_number"] > weights["mac_address"]
        assert weights["mac_address"] > weights["hostname"]
        assert weights["hostname"] > weights["ip_address"]

    def test_best_match_confidence(self):
        assert MatchWeights.best_match_confidence(["hostname", "ip_address"]) == 0.85
        assert MatchWeights.best_match_confidence(["agent_id"]) == 0.99
        assert MatchWeights.best_match_confidence([]) == 0.0


class TestSourceConfidence:
    def test_edr_high(self):
        assert SourceConfidence.get("crowdstrike") == 0.95
        assert SourceConfidence.get("sentinelone") == 0.95

    def test_scanner_moderate(self):
        assert SourceConfidence.get("qualys") == 0.80
        assert SourceConfidence.get("nessus") == 0.80

    def test_ndr_low(self):
        assert SourceConfidence.get("darktrace") == 0.60

    def test_siem_lowest(self):
        assert SourceConfidence.get("splunk") == 0.50

    def test_unknown_default(self):
        assert SourceConfidence.get("some_unknown") == 0.50

    def test_none_default(self):
        assert SourceConfidence.get("") == 0.50

    def test_case_insensitive(self):
        assert SourceConfidence.get("CrowdStrike") == 0.95
