"""Unauthorized device detection and lifecycle persistence."""

from __future__ import annotations

import time
from typing import Any

from .device_inventory import DeviceInventoryService
from .storage import JsonlStore

VALID_UNAUTHORIZED_DEVICE_STATUSES = ("new", "investigating", "approved", "blocked")


class UnauthorizedDeviceValidationError(ValueError):
    """Raised when unauthorized device updates are invalid."""


class UnauthorizedDeviceManager:
    """Tracks unmanaged observed assets and their review lifecycle."""

    def __init__(self, path: str = "unauthorized_devices.jsonl"):
        self._store = JsonlStore(path)

    def list_findings(
        self,
        *,
        inventory: DeviceInventoryService,
        alerts: list[dict] | None = None,
        incidents: list[dict] | None = None,
        limit: int = 200,
        status: str = "",
        query: str = "",
    ) -> list[dict[str, Any]]:
        observed = {
            str(device.get("ip", "")): device
            for device in inventory.list_devices(
                alerts=alerts or [],
                incidents=incidents or [],
                limit=500,
            )
            if device.get("ip") and not bool(device.get("managed"))
        }
        persisted = self._materialize_latest()
        ips = sorted(set(observed) | set(persisted))

        findings: list[dict[str, Any]] = []
        for ip in ips:
            device = observed.get(ip)
            state = persisted.get(ip, {})
            finding = {
                "ip": ip,
                "status": state.get("status", "new"),
                "notes": state.get("notes", ""),
                "owner": state.get("owner", ""),
                "reviewed_at": state.get("reviewed_at"),
                "updated_at": state.get("updated_at"),
                "observation_status": "observed" if device is not None else "cleared",
                "queue": "asset-security",
                "source_asset": device,
            }
            if device is not None:
                finding.update(
                    {
                        "hostname": device.get("hostname", ""),
                        "vendor": device.get("vendor", "unknown"),
                        "os": device.get("os", "unknown"),
                        "risk_score": int(device.get("risk_score", 0)),
                        "risk_level": device.get("risk_level", "low"),
                        "alert_count": int(device.get("alert_count", 0)),
                        "incident_count": int(device.get("incident_count", 0)),
                        "last_seen": device.get("last_seen", ""),
                        "open_ports": list(device.get("open_ports", [])),
                        "threat_types": list(device.get("threat_types", [])),
                        "tags": list(device.get("tags", [])),
                    }
                )
            else:
                finding.update(
                    {
                        "hostname": state.get("hostname", ""),
                        "vendor": state.get("vendor", "unknown"),
                        "os": state.get("os", "unknown"),
                        "risk_score": int(state.get("risk_score", 0)),
                        "risk_level": state.get("risk_level", "low"),
                        "alert_count": int(state.get("alert_count", 0)),
                        "incident_count": int(state.get("incident_count", 0)),
                        "last_seen": state.get("last_seen", ""),
                        "open_ports": list(state.get("open_ports", [])),
                        "threat_types": list(state.get("threat_types", [])),
                        "tags": list(state.get("tags", [])),
                    }
                )

            if status and str(finding.get("status", "")).lower() != str(status).lower():
                continue
            if query:
                q = str(query).strip().lower()
                searchable = " ".join(
                    [
                        str(finding.get("ip", "")),
                        str(finding.get("hostname", "")),
                        str(finding.get("vendor", "")),
                        str(finding.get("os", "")),
                        str(finding.get("owner", "")),
                        " ".join(finding.get("tags", [])),
                    ]
                ).lower()
                if q not in searchable:
                    continue

            findings.append(finding)

        findings.sort(
            key=lambda item: (
                item.get("observation_status") != "observed",
                item.get("status") == "approved",
                -int(item.get("risk_score", 0)),
                -int(item.get("incident_count", 0)),
                str(item.get("ip", "")),
            )
        )
        return findings[: max(1, min(int(limit), 500))]

    def get_finding(
        self,
        ip: str,
        *,
        inventory: DeviceInventoryService,
        alerts: list[dict] | None = None,
        incidents: list[dict] | None = None,
    ) -> dict[str, Any] | None:
        target = str(ip or "").strip()
        if not target:
            return None
        for finding in self.list_findings(
            inventory=inventory,
            alerts=alerts or [],
            incidents=incidents or [],
            limit=500,
        ):
            if finding.get("ip") == target:
                return finding
        return None

    def update_finding(
        self,
        ip: str,
        *,
        inventory: DeviceInventoryService,
        alerts: list[dict] | None = None,
        incidents: list[dict] | None = None,
        status: str | None = None,
        notes: str | None = None,
        owner: str | None = None,
    ) -> dict[str, Any] | None:
        current = self.get_finding(
            ip,
            inventory=inventory,
            alerts=alerts or [],
            incidents=incidents or [],
        )
        if current is None:
            return None

        updated = dict(current)
        if status is not None:
            normalized = str(status).strip().lower()
            if normalized not in VALID_UNAUTHORIZED_DEVICE_STATUSES:
                allowed = ", ".join(VALID_UNAUTHORIZED_DEVICE_STATUSES)
                raise UnauthorizedDeviceValidationError(f"status must be one of: {allowed}")
            updated["status"] = normalized
        if notes is not None:
            updated["notes"] = str(notes).strip()
        if owner is not None:
            updated["owner"] = str(owner).strip()

        now = time.time()
        updated["reviewed_at"] = now
        updated["updated_at"] = now
        self._store.append(
            {
                "ip": updated["ip"],
                "status": updated["status"],
                "notes": updated.get("notes", ""),
                "owner": updated.get("owner", ""),
                "reviewed_at": updated["reviewed_at"],
                "updated_at": updated["updated_at"],
                # Persist a compact snapshot so cleared findings remain visible.
                "hostname": updated.get("hostname", ""),
                "vendor": updated.get("vendor", "unknown"),
                "os": updated.get("os", "unknown"),
                "risk_score": updated.get("risk_score", 0),
                "risk_level": updated.get("risk_level", "low"),
                "alert_count": updated.get("alert_count", 0),
                "incident_count": updated.get("incident_count", 0),
                "last_seen": updated.get("last_seen", ""),
                "open_ports": list(updated.get("open_ports", [])),
                "threat_types": list(updated.get("threat_types", [])),
                "tags": list(updated.get("tags", [])),
            }
        )
        return self.get_finding(
            ip,
            inventory=inventory,
            alerts=alerts or [],
            incidents=incidents or [],
        )

    def _materialize_latest(self) -> dict[str, dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for record in self._store.read_all():
            ip = str(record.get("ip", "")).strip()
            if not ip:
                continue
            latest[ip] = dict(record)
        return latest
