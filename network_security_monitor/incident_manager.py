"""Incident case persistence helpers."""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import List

from .models import Alert


class IncidentManager:
    """Stores and retrieves incident cases using JSONL persistence."""

    def __init__(self, path: str = "incidents.jsonl"):
        self._path = path

    def create_case(self, alert: Alert, queue: str = "soc-triage") -> dict:
        now = time.time()
        incident_id = self._build_id(alert, now)
        case = {
            "incident_id": incident_id,
            "created_at": now,
            "status": "open",
            "queue": queue,
            "severity": alert.severity.value,
            "threat_type": alert.threat_type.value,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "dst_port": alert.dst_port,
            "description": alert.description,
            "metadata": alert.metadata,
        }
        self._append(case)
        return case

    def list_cases(self, limit: int = 200) -> List[dict]:
        if not os.path.exists(self._path):
            return []
        try:
            with open(self._path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return []
        cases = []
        for raw in reversed(lines):
            try:
                cases.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
            if len(cases) >= limit:
                break
        return list(reversed(cases))

    def _append(self, payload: dict) -> None:
        directory = os.path.dirname(self._path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload))
            fh.write("\n")

    @staticmethod
    def _build_id(alert: Alert, now: float) -> str:
        base = f"{alert.threat_type.value}|{alert.src_ip}|{now}"
        digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]
        return f"INC-{digest.upper()}"
