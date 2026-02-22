"""Tests for hostname, IP, and MAC normalizers."""


from secimport.normalizers.hostname import normalize_hostname, normalize_ip, normalize_mac


class TestNormalizeHostname:
    def test_basic(self):
        assert normalize_hostname("WEB01") == "web01"

    def test_strip_whitespace(self):
        assert normalize_hostname("  DB-Server  ") == "db-server"

    def test_strip_local_suffix(self):
        assert normalize_hostname("app01.local") == "app01"

    def test_strip_corp_suffix(self):
        assert normalize_hostname("WEB01.Corp.LOCAL") == "web01.corp"
        # Only strips the last matching suffix

    def test_strip_internal_suffix(self):
        assert normalize_hostname("db01.internal") == "db01"

    def test_no_strip_domain(self):
        assert normalize_hostname("app01.prod.example.com", strip_domain=False) == (
            "app01.prod.example.com"
        )

    def test_none(self):
        assert normalize_hostname(None) is None

    def test_empty(self):
        assert normalize_hostname("") is None
        assert normalize_hostname("   ") is None


class TestNormalizeIP:
    def test_ipv4(self):
        assert normalize_ip("10.0.0.1") == "10.0.0.1"

    def test_strip_whitespace(self):
        assert normalize_ip("  10.0.0.1  ") == "10.0.0.1"

    def test_ipv6(self):
        result = normalize_ip("::1")
        assert result == "::1"

    def test_invalid(self):
        assert normalize_ip("not-an-ip") is None

    def test_none(self):
        assert normalize_ip(None) is None

    def test_empty(self):
        assert normalize_ip("") is None


class TestNormalizeMAC:
    def test_colon_separated(self):
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_dash_separated(self):
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    def test_cisco_format(self):
        assert normalize_mac("AABB.CCDD.EEFF") == "aa:bb:cc:dd:ee:ff"

    def test_no_separator(self):
        assert normalize_mac("AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff"

    def test_already_normalized(self):
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"

    def test_invalid_length(self):
        assert normalize_mac("AA:BB:CC") is None

    def test_invalid_chars(self):
        assert normalize_mac("GG:HH:II:JJ:KK:LL") is None

    def test_none(self):
        assert normalize_mac(None) is None

    def test_empty(self):
        assert normalize_mac("") is None
