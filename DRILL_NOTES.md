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

---

Date: 2026-04-03 (Session 2)
Profile: `office_tuned`
Runbook reference: `RUNBOOK.md`

## Scope
- Operational validation of:
  - live capture path
  - alert quality under baseline traffic
  - Slack + SIEM dual delivery
  - runbook triage/containment workflow

## Procedure
- Executed:
  - `.\.venv\Scripts\python.exe main.py --live --profile office_tuned --live-duration 30 --save-tuning tuning-live.json --no-dashboard`
  - `.\.venv\Scripts\python.exe main.py --simulate --profile office_tuned --no-dashboard`
- Enabled integrations in `.env`:
  - `NSM_SLACK_WEBHOOK_URL`
  - `NSM_SIEM_OUTPUT_FILE=siem/alerts.jsonl`

## Observed Alerts
- Live sample (30s):
  - `PORT_SCAN | HIGH | 192.168.1.1 -> 192.168.1.35`
  - `UNUSUAL_TRAFFIC | MEDIUM | 198.169.1.1 -> 192.168.1.35`
  - `UNUSUAL_TRAFFIC | MEDIUM | 192.168.1.35 -> 198.169.1.1`
- Simulation sample:
  - `PORT_SCAN | HIGH | 10.0.0.99`
  - `BRUTE_FORCE | HIGH | 10.0.99.2`
  - `PHISHING_ATTEMPT | HIGH | 10.0.99.6`
  - `DDOS | CRITICAL | 10.0.99.5`

## Triage Outcome
- `tuning-live.json` from live run reports:
  - `alerts_per_minute=7.84`
  - suggestion: `Current thresholds look stable for this traffic sample.`
- No threshold change applied after this run.

## Containment Plan (executed as drill checklist)
- `PORT_SCAN`:
  - mark source for short-term firewall rate limit and watchlist.
- `UNUSUAL_TRAFFIC`:
  - confirm change windows and host role before blocking.
- `BRUTE_FORCE` / `PHISHING_ATTEMPT` / `DDOS`:
  - follow runbook Section 3 controls (credential resets, IOC blocking, temporary volumetric controls).

## Evidence Checklist
- Preserved:
  - `alerts.log`
  - `tuning-live.json`
  - `siem/alerts.jsonl` (validated append behavior)
- Integration status validated in runtime output:
  - `Configured: Slack webhook, SIEM file (siem/alerts.jsonl)`

## Follow-ups
- Execute full 30-minute live trial command on demand:
  - `.\.venv\Scripts\python.exe main.py --live --profile office_tuned --live-duration 1800 --save-tuning tuning-live.json --no-dashboard`
- If live environment shows sustained false positives:
  - increase `TRAFFIC_ANOMALY_MIN_PACKETS` by +10%
  - or increase `TRAFFIC_ANOMALY_MULTIPLIER` by +0.2

---

Date: 2026-04-03 (Session 3)
Profile: `office_tuned`
Runbook reference: `RUNBOOK.md`

## Scope
- Full 30-minute live capture trial with production-style integrations enabled.

## Procedure
- Executed:
  - `.\.venv\Scripts\python.exe main.py --live --profile office_tuned --live-duration 1800 --save-tuning tuning-live.json --no-dashboard`
- Integrations active from `.env`:
  - Slack webhook
  - SIEM file output (`siem/alerts.jsonl`)

## Observed Alerts
- `PORT_SCAN | HIGH | 192.168.1.1 -> 192.168.1.35` (4 total during 30m)
- Distinct ports observed included bursts up to `58` ports in 15s.

## Triage Outcome
- Runtime tuning output:
  - `alerts_total=4`
  - `alerts_per_minute=0.13`
  - suggestion: `Current thresholds look stable for this traffic sample.`
- Outcome: keep `office_tuned` unchanged.

## Evidence Checklist
- Preserved:
  - `tuning-live.json` (updated from the full run)
  - `siem/alerts.jsonl` (size increased to 3258 bytes, appended records validated)
  - `alerts.log`

## Follow-ups
- Investigate recurring source `192.168.1.1`:
  - confirm if this is trusted network discovery/management traffic
  - if trusted, allowlist source or raise `PORT_SCAN_THRESHOLD` slightly for this segment
