# Drill Notes

Date: 2026-04-03
Profile: `office`
Runbook reference: `RUNBOOK.md`

## Scope
- Tabletop drill focused on:
  - `BRUTE_FORCE`
  - `DATA_EXFILTRATION`

## Procedure
- Used synthetic packet replay via `NetworkMonitor` to trigger both scenarios.
- Thresholds temporarily set for drill:
  - `BRUTE_FORCE_THRESHOLD=5`
  - `DATA_EXFIL_THRESHOLD_BYTES=2000`

## Observed Alerts
- `BRUTE_FORCE | HIGH | 172.16.50.10`
- `DATA_EXFILTRATION | CRITICAL | 10.0.20.5`

## Triage Outcome
- Alert parsing and correlation path works for both requested threat classes.
- Alert manager stored and emitted both alerts with expected severities.

## Containment Plan (from runbook)
- Brute force:
  - Lock target account and enforce password reset.
  - Block/ratelimit source `172.16.50.10` at edge controls.
- Data exfiltration:
  - Isolate host `10.0.20.5`.
  - Block destination `203.0.113.99` pending investigation.

## Evidence Checklist
- Preserve:
  - `alerts.log`
  - recent NSM alert history
  - firewall/identity logs for affected source and destination IPs

## Follow-ups
- Live baseline capture is currently blocked on this host due missing packet capture driver:
  - Scapy reports no layer-2 sniffing support (`winpcap/npcap` not installed).
- Install Npcap, rerun:
  - `.\.venv\Scripts\python.exe main.py --list-interfaces`
  - `.\.venv\Scripts\python.exe main.py --live --profile office --live-duration 1800 --save-tuning tuning-live.json`
