"""Device inventory and asset-context helpers."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _to_timestamp(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _severity_weight(value: str) -> int:
    return {
        "LOW": 10,
        "MEDIUM": 25,
        "HIGH": 45,
        "CRITICAL": 70,
    }.get(str(value or "").upper(), 0)


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _isoish(value) -> str:
    ts = _to_timestamp(value)
    if ts is None:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


class DeviceInventoryService:
    """Builds lightweight device inventory records from local context."""

    def __init__(self, seed_path: str = ""):
        self._seed_path = seed_path.strip()

    def list_devices(
        self,
        *,
        alerts: list[dict] | None = None,
        incidents: list[dict] | None = None,
        limit: int = 200,
        risk_level: str = "",
        query: str = "",
    ) -> list[dict[str, Any]]:
        devices = self._build_inventory(alerts=alerts or [], incidents=incidents or [])
        query_value = (query or "").strip().lower()
        risk_value = (risk_level or "").strip().lower()
        if query_value:
            devices = [
                device
                for device in devices
                if query_value in str(device.get("ip", "")).lower()
                or query_value in str(device.get("hostname", "")).lower()
                or query_value in str(device.get("vendor", "")).lower()
                or query_value in str(device.get("os", "")).lower()
                or query_value in " ".join(device.get("tags", [])).lower()
            ]
        if risk_value:
            devices = [device for device in devices if str(device.get("risk_level", "")).lower() == risk_value]
        return devices[: max(1, min(int(limit), 500))]

    def get_device(
        self,
        ip: str,
        *,
        alerts: list[dict] | None = None,
        incidents: list[dict] | None = None,
    ) -> dict[str, Any] | None:
        normalized_ip = (ip or "").strip()
        if not normalized_ip:
            return None
        for device in self._build_inventory(alerts=alerts or [], incidents=incidents or []):
            if device.get("ip") == normalized_ip:
                return device
        return None

    def enrich_incident(
        self,
        incident: dict[str, Any] | None,
        *,
        alerts: list[dict] | None = None,
        incidents: list[dict] | None = None,
    ) -> dict[str, Any] | None:
        if not incident:
            return None
        enriched = dict(incident)
        src_ip = str(enriched.get("src_ip", "")).strip()
        if src_ip:
            enriched["source_asset"] = self.get_device(
                src_ip,
                alerts=alerts or [],
                incidents=incidents or [],
            )
        return enriched

    def _build_inventory(self, *, alerts: list[dict], incidents: list[dict]) -> list[dict[str, Any]]:
        seeds = self._load_seed_records()
        assets: dict[str, dict[str, Any]] = {}

        for record in seeds:
            ip = str(record.get("ip", "")).strip()
            if not ip:
                continue
            assets[ip] = {
                "ip": ip,
                "hostname": str(record.get("hostname", "")).strip(),
                "mac": str(record.get("mac", "")).strip(),
                "vendor": str(record.get("vendor", "")).strip() or "unknown",
                "os": str(record.get("os", "")).strip() or "unknown",
                "role": str(record.get("role", "")).strip(),
                "zone": str(record.get("zone", "")).strip(),
                "tags": self._normalize_tags(record.get("tags") or []),
                "open_ports": self._normalize_ports(record.get("open_ports") or []),
                "risk_score": max(0, min(int(record.get("risk_score", 0) or 0), 100)),
                "risk_level": str(record.get("risk_level", "")).strip().lower(),
                "managed": True,
                "inventory_source": "seed",
                "alert_count": 0,
                "incident_count": 0,
                "last_seen": "",
                "last_seen_ts": 0.0,
                "threat_types": [],
            }

        alert_counts: dict[str, int] = defaultdict(int)
        incident_counts: dict[str, int] = defaultdict(int)
        severity_scores: dict[str, int] = defaultdict(int)
        threat_types: dict[str, set[str]] = defaultdict(set)
        open_ports: dict[str, set[int]] = defaultdict(set)
        last_seen: dict[str, float] = defaultdict(float)

        for alert in alerts:
            ip = str(alert.get("src_ip", "")).strip()
            if not ip:
                continue
            asset = assets.setdefault(ip, self._blank_asset(ip))
            alert_counts[ip] += 1
            severity_scores[ip] += _severity_weight(alert.get("severity", ""))
            threat = str(alert.get("threat_type", "")).strip()
            if threat:
                threat_types[ip].add(threat)
            port = alert.get("dst_port")
            if isinstance(port, int):
                open_ports[ip].add(port)
            seen_ts = _to_timestamp(alert.get("timestamp"))
            if seen_ts and seen_ts > last_seen[ip]:
                last_seen[ip] = seen_ts
            self._hydrate_asset_from_metadata(asset, alert.get("metadata") or {})

        for incident in incidents:
            ip = str(incident.get("src_ip", "")).strip()
            if not ip:
                continue
            asset = assets.setdefault(ip, self._blank_asset(ip))
            incident_counts[ip] += 1
            severity_scores[ip] += _severity_weight(incident.get("severity", ""))
            threat = str(incident.get("threat_type", "")).strip()
            if threat:
                threat_types[ip].add(threat)
            port = incident.get("dst_port")
            if isinstance(port, int):
                open_ports[ip].add(port)
            for when in ("resolved_at", "contained_at", "assigned_at", "updated_at", "created_at"):
                seen_ts = _to_timestamp(incident.get(when))
                if seen_ts and seen_ts > last_seen[ip]:
                    last_seen[ip] = seen_ts
            self._hydrate_asset_from_metadata(asset, incident.get("metadata") or {})

        results: list[dict[str, Any]] = []
        for ip, asset in assets.items():
            risk_score = max(
                asset.get("risk_score", 0),
                min(
                    100,
                    severity_scores[ip]
                    + min(alert_counts[ip] * 6, 18)
                    + min(incident_counts[ip] * 10, 30)
                    + min(len(open_ports[ip]) * 4, 12),
                ),
            )
            device = dict(asset)
            device["alert_count"] = alert_counts[ip]
            device["incident_count"] = incident_counts[ip]
            device["open_ports"] = sorted(set(device.get("open_ports") or []).union(open_ports[ip]))
            device["risk_score"] = risk_score
            device["risk_level"] = device.get("risk_level") or _risk_level(risk_score)
            device["threat_types"] = sorted(set(device.get("threat_types") or []).union(threat_types[ip]))
            device["last_seen_ts"] = last_seen[ip]
            device["last_seen"] = _isoish(last_seen[ip]) if last_seen[ip] else ""
            device["tags"] = self._normalize_tags(device.get("tags") or [])
            results.append(device)

        results.sort(
            key=lambda item: (
                -int(item.get("risk_score", 0)),
                -int(item.get("incident_count", 0)),
                -int(item.get("alert_count", 0)),
                str(item.get("ip", "")),
            )
        )
        return results

    @staticmethod
    def _blank_asset(ip: str) -> dict[str, Any]:
        return {
            "ip": ip,
            "hostname": "",
            "mac": "",
            "vendor": "unknown",
            "os": "unknown",
            "role": "",
            "zone": "",
            "tags": [],
            "open_ports": [],
            "risk_score": 0,
            "risk_level": "",
            "managed": False,
            "inventory_source": "observed",
            "alert_count": 0,
            "incident_count": 0,
            "last_seen": "",
            "last_seen_ts": 0.0,
            "threat_types": [],
        }

    @staticmethod
    def _normalize_ports(values) -> list[int]:
        ports: list[int] = []
        for value in values or []:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 0 < port <= 65535:
                ports.append(port)
        return sorted(set(ports))

    @staticmethod
    def _normalize_tags(values) -> list[str]:
        tags = [str(value).strip() for value in values if str(value).strip()]
        return sorted(set(tags))

    def _hydrate_asset_from_metadata(self, asset: dict[str, Any], metadata: dict[str, Any]) -> None:
        hostname = str(metadata.get("hostname", "")).strip()
        mac = str(metadata.get("mac", "")).strip()
        vendor = str(metadata.get("vendor", "")).strip()
        os_name = str(metadata.get("os", "")).strip()
        zone = str(metadata.get("zone", "")).strip()
        role = str(metadata.get("role", "")).strip()
        if hostname and not asset.get("hostname"):
            asset["hostname"] = hostname
        if mac and not asset.get("mac"):
            asset["mac"] = mac
        if vendor and asset.get("vendor") in ("", "unknown"):
            asset["vendor"] = vendor
        if os_name and asset.get("os") in ("", "unknown"):
            asset["os"] = os_name
        if zone and not asset.get("zone"):
            asset["zone"] = zone
        if role and not asset.get("role"):
            asset["role"] = role
        asset["open_ports"] = self._normalize_ports(
            list(asset.get("open_ports") or []) + list(metadata.get("open_ports") or [])
        )
        asset["tags"] = self._normalize_tags(list(asset.get("tags") or []) + list(metadata.get("tags") or []))

    def _load_seed_records(self) -> list[dict[str, Any]]:
        if not self._seed_path:
            return []
        path = Path(self._seed_path)
        if not path.exists() or not path.is_file():
            return []
        try:
            with open(path, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []

        if isinstance(payload, dict):
            records = payload.get("devices", [])
        else:
            records = payload
        if not isinstance(records, list):
            return []
        return [record for record in records if isinstance(record, dict)]
