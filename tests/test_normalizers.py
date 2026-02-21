"""Tests for severity normalization."""

import pytest

from secimport.normalizers import normalize_severity


class TestNormalizeSeverity:
    @pytest.mark.parametrize(
        ("value", "scanner", "expected"),
        [
            # Qualys numeric
            ("5", "qualys", "Critical"),
            ("4", "qualys", "High"),
            ("3", "qualys", "Medium"),
            ("2", "qualys", "Low"),
            ("1", "qualys", "Low"),
            # Nessus text
            ("Critical", "nessus", "Critical"),
            ("High", "nessus", "High"),
            ("Medium", "nessus", "Medium"),
            ("Low", "nessus", "Low"),
            ("Info", "nessus", "Low"),
            # Tenable
            ("Informational", "tenable", "Low"),
            # Rapid7
            ("Severe", "rapid7", "Critical"),
            ("Moderate", "rapid7", "Medium"),
            # OpenVAS
            ("High", "openvas", "Critical"),
            ("Log", "openvas", "Low"),
            # Generic fallback
            ("critical", "generic", "Critical"),
            ("HIGH", "generic", "High"),
        ],
    )
    def test_mappings(self, value: str, scanner: str, expected: str):
        assert normalize_severity(value, scanner) == expected

    def test_none_returns_low(self):
        assert normalize_severity(None) == "Low"

    def test_unknown_scanner_uses_generic(self):
        assert normalize_severity("Critical", "unknown_scanner") == "Critical"

    def test_unknown_value_returns_low(self):
        assert normalize_severity("Bogus", "nessus") == "Low"

    def test_integer_value(self):
        assert normalize_severity(5, "qualys") == "Critical"

    def test_case_insensitive(self):
        assert normalize_severity("critical", "nessus") == "Critical"
        assert normalize_severity("HIGH", "rapid7") == "High"
