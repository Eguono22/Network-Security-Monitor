"""Topology, zone inference, and cross-zone policy evaluation."""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


class NetworkTopologyService:
    """Loads topology configuration and evaluates observed zone paths."""

    def __init__(self, path: str = ""):
        self._path = path.strip()

    def summarize(
        self,
        *,
        devices: list[dict] | None = None,
        alerts: list[dict] | None = None,
        incidents: list[dict] | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        topology = self._load_topology()
        zone_names = {zone.get("name", "") for zone in topology["zones"] if zone.get("name")}

        device_zone_index: dict[str, str] = {}
        zone_assets: dict[str, int] = defaultdict(int)
        for device in devices or []:
            ip = str(device.get("ip", "")).strip()
            zone = self._device_zone(device, topology)
            if ip and zone:
                device_zone_index[ip] = zone
                zone_assets[zone] += 1
                zone_names.add(zone)

        edges: dict[tuple[str, str], dict[str, Any]] = {}
        for record in list(alerts or []) + list(incidents or []):
            src_ip = str(record.get("src_ip", "")).strip()
            dst_ip = str(record.get("dst_ip", "")).strip()
            if not src_ip or not dst_ip:
                continue
            src_zone = device_zone_index.get(src_ip) or self.resolve_zone(src_ip, topology=topology)
            dst_zone = device_zone_index.get(dst_ip) or self.resolve_zone(dst_ip, topology=topology)
            if not src_zone or not dst_zone or src_zone == dst_zone:
                continue
            zone_names.add(src_zone)
            zone_names.add(dst_zone)
            policy = self._policy_for(src_zone, dst_zone, topology)
            key = (src_zone, dst_zone)
            edge = edges.setdefault(
                key,
                {
                    "src_zone": src_zone,
                    "dst_zone": dst_zone,
                    "observation_count": 0,
                    "risk_score": 0,
                    "status": policy.get("status", "unknown"),
                    "policy_name": policy.get("name", ""),
                    "sample_threats": set(),
                    "src_ips": set(),
                    "dst_ips": set(),
                },
            )
            edge["observation_count"] += 1
            edge["risk_score"] = max(edge["risk_score"], int(policy.get("risk_score", 20)))
            threat = str(record.get("threat_type", "")).strip()
            if threat:
                edge["sample_threats"].add(threat)
            edge["src_ips"].add(src_ip)
            edge["dst_ips"].add(dst_ip)

        rendered_edges = []
        for edge in edges.values():
            rendered_edges.append(
                {
                    "src_zone": edge["src_zone"],
                    "dst_zone": edge["dst_zone"],
                    "status": edge["status"],
                    "policy_name": edge["policy_name"],
                    "observation_count": edge["observation_count"],
                    "risk_score": edge["risk_score"],
                    "sample_threats": sorted(edge["sample_threats"]),
                    "sample_src_ips": sorted(edge["src_ips"])[:3],
                    "sample_dst_ips": sorted(edge["dst_ips"])[:3],
                }
            )

        rendered_edges.sort(
            key=lambda item: (
                item["status"] == "allowed",
                -int(item["risk_score"]),
                -int(item["observation_count"]),
                item["src_zone"],
                item["dst_zone"],
            )
        )

        zones = []
        for zone in topology["zones"]:
            name = str(zone.get("name", "")).strip()
            if not name:
                continue
            zones.append(
                {
                    "name": name,
                    "label": str(zone.get("label", "")).strip() or name,
                    "cidrs": list(zone.get("cidrs", [])),
                    "description": str(zone.get("description", "")).strip(),
                    "asset_count": zone_assets.get(name, 0),
                }
            )
        existing = {zone["name"] for zone in zones}
        for inferred in sorted(name for name in zone_names if name and name not in existing):
            zones.append(
                {
                    "name": inferred,
                    "label": inferred,
                    "cidrs": [],
                    "description": "",
                    "asset_count": zone_assets.get(inferred, 0),
                }
            )

        return {
            "zones": zones[: max(1, min(int(limit), 500))],
            "observed_paths": rendered_edges[: max(1, min(int(limit), 500))],
            "violations": [edge for edge in rendered_edges if edge["status"] != "allowed"][: max(1, min(int(limit), 500))],
            "policy_count": len(topology["policies"]),
        }

    def resolve_zone(self, ip: str, *, topology: dict[str, Any] | None = None) -> str:
        target = str(ip or "").strip()
        if not target:
            return ""
        topo = topology or self._load_topology()
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return ""
        for zone in topo["zones"]:
            for cidr in zone.get("cidrs", []):
                try:
                    if addr in ipaddress.ip_network(str(cidr), strict=False):
                        return str(zone.get("name", "")).strip()
                except ValueError:
                    continue
        return ""

    def enrich_incident(
        self,
        incident: dict[str, Any] | None,
        *,
        devices: list[dict] | None = None,
    ) -> dict[str, Any] | None:
        if not incident:
            return None
        topology = self._load_topology()
        enriched = dict(incident)
        device_index = {str(device.get("ip", "")).strip(): device for device in devices or [] if device.get("ip")}
        src_ip = str(enriched.get("src_ip", "")).strip()
        dst_ip = str(enriched.get("dst_ip", "")).strip()
        src_zone = self._device_zone(device_index.get(src_ip, {}), topology) or self.resolve_zone(src_ip, topology=topology)
        dst_zone = self._device_zone(device_index.get(dst_ip, {}), topology) or self.resolve_zone(dst_ip, topology=topology)
        policy = self._policy_for(src_zone, dst_zone, topology) if src_zone and dst_zone and src_zone != dst_zone else {}
        enriched["zone_context"] = {
            "src_zone": src_zone or "",
            "dst_zone": dst_zone or "",
            "path_status": policy.get("status", "same-zone" if src_zone and src_zone == dst_zone else "unknown"),
            "policy_name": policy.get("name", ""),
        }
        return enriched

    def _device_zone(self, device: dict[str, Any], topology: dict[str, Any]) -> str:
        explicit = str((device or {}).get("zone", "")).strip()
        if explicit:
            return explicit
        ip = str((device or {}).get("ip", "")).strip()
        return self.resolve_zone(ip, topology=topology)

    @staticmethod
    def _policy_for(src_zone: str, dst_zone: str, topology: dict[str, Any]) -> dict[str, Any]:
        for policy in topology["policies"]:
            if (
                str(policy.get("src_zone", "")).strip() == src_zone
                and str(policy.get("dst_zone", "")).strip() == dst_zone
            ):
                allowed = bool(policy.get("allowed", True))
                return {
                    "name": str(policy.get("name", "")).strip(),
                    "status": "allowed" if allowed else "blocked",
                    "risk_score": 15 if allowed else 80,
                }
        return {"name": "", "status": "unknown", "risk_score": 55}

    def _load_topology(self) -> dict[str, Any]:
        zones: list[dict[str, Any]] = []
        policies: list[dict[str, Any]] = []
        if self._path:
            path = Path(self._path)
            if path.exists() and path.is_file():
                try:
                    with open(path, encoding="utf-8") as fh:
                        payload = json.load(fh)
                except (OSError, json.JSONDecodeError):
                    payload = {}
                if isinstance(payload, dict):
                    raw_zones = payload.get("zones", [])
                    raw_policies = payload.get("policies", payload.get("paths", []))
                    if isinstance(raw_zones, list):
                        zones = [zone for zone in raw_zones if isinstance(zone, dict)]
                    if isinstance(raw_policies, list):
                        policies = [policy for policy in raw_policies if isinstance(policy, dict)]
        return {"zones": zones, "policies": policies}
