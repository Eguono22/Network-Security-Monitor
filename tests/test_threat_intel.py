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
