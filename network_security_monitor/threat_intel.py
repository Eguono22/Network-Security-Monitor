"""Mock threat-intelligence enrichment helpers."""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any, Iterable


class ThreatIntelService:
    """Provides deterministic local enrichment without external dependencies."""

    def __init__(self, known_malicious_ips: Iterable[str] | None = None):
        self._known_malicious_ips = {
            str(value).strip() for value in (known_malicious_ips or set()) if str(value).strip()
        }

    def lookup(
        self,
        indicator: str,
        *,
        indicator_type: str = "",
        alerts: list[dict[str, Any]] | None = None,
        incidents: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        value = str(indicator).strip()
        resolved_type = self._resolve_indicator_type(value, indicator_type)
        related_alerts = self._match_records(value, resolved_type, alerts or [])
        related_incidents = self._match_records(value, resolved_type, incidents or [])

        tags = ["mock-intel"]
        sources: list[dict[str, Any]] = [{"name": "sentinelnet-mock-intel", "confidence": 0.55}]
        verdict = "unknown"
        confidence = 0.35
        reputation = 35
        summary = "No strong local intelligence signal found."

        if resolved_type == "ip":
            ip = ipaddress.ip_address(value)
            if ip.is_private:
                verdict = "internal"
                confidence = 0.2
                reputation = 10
                tags.append("internal-address")
                summary = "Private IP address observed in local monitoring context."
            else:
                verdict = "benign"
                confidence = 0.3
                reputation = 30
                summary = "Public IP with no strong local malicious signal."

            if value in self._known_malicious_ips:
                verdict = "malicious"
                confidence = 0.96
                reputation = 95
                tags.extend(["watchlist-match", "known-malicious-ip"])
                sources.append({"name": "local-watchlist", "confidence": 0.96})
                summary = "Indicator matched the configured local malicious IP list."
        elif resolved_type == "domain":
            verdict = "benign"
            confidence = 0.3
            reputation = 30
            summary = "Domain did not match a strong local threat signal."
            lowered = value.lower()
            phishing_terms = ("login", "verify", "account", "secure", "update")
            if any(term in lowered for term in phishing_terms):
                verdict = "suspicious"
                confidence = 0.72
                reputation = 68
                tags.extend(["phishing-keyword", "brand-impersonation-risk"])
                sources.append({"name": "mock-phishing-heuristic", "confidence": 0.72})
                summary = "Domain contains phishing-style keywords used in the local heuristic."

        if related_alerts:
            alert_tags = self._threat_tags(related_alerts)
            tags.extend(alert_tags)
            tags.append("recent-alert-match")
            severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            highest = max(severity_rank.get(str(a.get("severity", "")).upper(), 0) for a in related_alerts)
            if highest >= 4:
                verdict = "malicious"
                confidence = max(confidence, 0.9)
                reputation = max(reputation, 88)
            elif highest >= 3:
                verdict = "suspicious" if verdict != "malicious" else verdict
                confidence = max(confidence, 0.78)
                reputation = max(reputation, 72)
            summary = f"Observed in {len(related_alerts)} recent alert(s) within local monitoring data."

        if related_incidents:
            tags.append("incident-linked")
            if verdict != "malicious":
                verdict = "suspicious"
            confidence = max(confidence, 0.8)
            reputation = max(reputation, 76)
            summary = f"Linked to {len(related_incidents)} recent incident case(s)."

        tags = self._dedupe(tags)
        return {
            "indicator": value,
            "indicator_type": resolved_type,
            "verdict": verdict,
            "confidence": round(confidence, 2),
            "reputation_score": reputation,
            "summary": summary,
            "tags": tags,
            "sources": sources,
            "related": {
                "alerts": len(related_alerts),
                "incidents": len(related_incidents),
            },
            "recent_threats": self._top_threats(related_alerts, related_incidents),
        }

    @staticmethod
    def _resolve_indicator_type(indicator: str, indicator_type: str) -> str:
        raw = str(indicator_type).strip().lower()
        if raw in {"ip", "domain", "url"}:
            return raw
        try:
            ipaddress.ip_address(indicator)
        except ValueError:
            pass
        else:
            return "ip"
        if indicator.startswith(("http://", "https://")):
            return "url"
        if "." in indicator:
            return "domain"
        return "unknown"

    def _match_records(
        self,
        indicator: str,
        indicator_type: str,
        records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if indicator_type == "ip":
            return [
                record for record in records
                if str(record.get("src_ip", "")) == indicator or str(record.get("dst_ip", "")) == indicator
            ]

        if indicator_type in {"domain", "url"}:
            lowered = indicator.lower()
            return [
                record for record in records
                if lowered in str(record.get("description", "")).lower()
                or lowered in str(record.get("raw", "")).lower()
                or lowered in str(record.get("metadata", {})).lower()
            ]

        return []

    @staticmethod
    def _threat_tags(records: list[dict[str, Any]]) -> list[str]:
        tags = []
        for record in records:
            threat = str(record.get("threat_type", "")).strip().lower()
            if threat:
                tags.append(f"threat:{threat}")
        return tags

    @staticmethod
    def _top_threats(
        alerts: list[dict[str, Any]],
        incidents: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        counter = Counter(
            str(record.get("threat_type", "")).upper()
            for record in [*alerts, *incidents]
            if str(record.get("threat_type", "")).strip()
        )
        return [
            {"threat_type": threat_type, "count": count}
            for threat_type, count in counter.most_common(3)
        ]

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        seen: set[str] = set()
        output: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            output.append(value)
        return output
