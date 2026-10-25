"""Tests for mock threat-intelligence enrichment."""

from network_security_monitor.threat_intel import ThreatIntelService


class TestThreatIntelService:
    def test_lookup_marks_watchlist_ip_as_malicious(self):
        service = ThreatIntelService({"198.51.100.7"})
        payload = service.lookup("198.51.100.7")
        assert payload["indicator_type"] == "ip"
        assert payload["verdict"] == "malicious"
        assert "watchlist-match" in payload["tags"]

    def test_lookup_uses_domain_keyword_heuristic(self):
        service = ThreatIntelService()
        payload = service.lookup("secure-login-verify.example")
        assert payload["indicator_type"] == "domain"
        assert payload["verdict"] == "suspicious"
        assert "phishing-keyword" in payload["tags"]


def test_lookup_rejects_invalid_explicit_ip():
    import pytest

    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        ThreatIntelService().lookup("not-an-address", indicator_type="ip")


def test_lookup_rejects_empty_and_oversized_indicators():
    import pytest

    for indicator in (" ", "a" * 2049):
        with pytest.raises(ValueError):
            ThreatIntelService().lookup(indicator)
