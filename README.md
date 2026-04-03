# Network Security Monitor

A Network Security Monitor (NSM) that continuously observes, analyzes, and detects suspicious activity across a network. It identifies cyber threats such as unauthorized access attempts, malware/C2 behavior, phishing indicators, potential data leaks, and unusual traffic patterns.

---

## Features

| Threat Type | Detection Method |
|---|---|
| **Port Scan** | Single source IP contacting ≥ N distinct ports within a time window |
| **SYN Flood** | High rate of TCP SYN packets from one source |
| **Brute Force** | Repeated connection attempts to authentication ports (SSH, RDP, FTP, …) |
| **DDoS** | Very high packet rate from a single source IP |
| **DNS Tunneling** | Oversized DNS query payloads (data exfiltration) |
| **Suspicious Port** | Connections to known back-door / C2 ports (4444, 1337, 31337, …) |
| **Malicious IP** | Traffic to/from threat-intelligence-listed IPs |
| **Phishing Attempt** | IOC/keyword match in DNS/HTTP/HTTPS payload content |
| **Data Exfiltration** | High outbound byte volume from one source in a short window |
| **Unusual Traffic** | Source packet-rate spike versus rolling baseline |

---

## Project Structure

```
network_security_monitor/
├── __init__.py          – Public API re-exports
├── config.py            – Configurable thresholds and settings
├── models.py            – Data classes: Packet, Alert, TrafficStats
├── packet_analyzer.py   – Scapy → Packet conversion
├── threat_detector.py   – All detection logic (10 detectors)
├── alert_manager.py     – Alert storage, logging, and callback integrations
├── monitor.py           – Main coordinator; live capture or replay mode
└── dashboard.py         – Real-time CLI dashboard

tests/
├── test_models.py
├── test_packet_analyzer.py
├── test_threat_detector.py
├── test_alert_manager.py
└── test_monitor.py

main.py                  – CLI entry point
requirements.txt
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

### Simulation (no root required)

Feed simulated attack traffic to demonstrate all detectors:

```bash
python main.py --simulate
```

With text-only output (no dashboard):

```bash
python main.py --simulate --no-dashboard
```

Fast integration wiring (without editing files):

```bash
python main.py --simulate --no-dashboard \
  --slack-webhook-url https://hooks.slack.com/services/XXX/YYY/ZZZ \
  --notify-min-severity HIGH
python main.py --simulate --no-dashboard --siem-output-file siem/alerts.jsonl
```

### Live Capture (requires root / CAP_NET_RAW)

```bash
sudo python main.py --live
sudo python main.py --live --interface eth0
python main.py --list-interfaces
python main.py --live --interface eth0 --live-duration 1800
python main.py --live --profile office
```

After simulation/live runs, NSM now prints:
- integration readiness (`Slack/webhook/email/SIEM` configured or not)
- tuning guidance based on observed alert volume

### View Past Alerts

```bash
python main.py --show-alerts alerts.log
```

### Vercel Deployment (API only)

This repository now includes a minimal serverless entrypoint at `api/index.py`
for Vercel Python runtime compatibility.

- `GET /` returns service metadata
- `GET /health` returns a health check response

Note: live packet capture (`--live`) requires raw network access and a
long-running process, so it must run on a VM/container host rather than Vercel.

---

## Configuration

Edit `network_security_monitor/config.py` to adjust detection thresholds.  
Key settings:

```python
Config.PORT_SCAN_THRESHOLD      = 25   # distinct ports in PORT_SCAN_TIME_WINDOW seconds
Config.PORT_SCAN_TRUSTED_SOURCES = {"192.168.1.1"}  # optional allowlist for known internal scanners
Config.SYN_FLOOD_THRESHOLD      = 200  # SYN packets per second
Config.BRUTE_FORCE_THRESHOLD    = 12   # attempts per BRUTE_FORCE_TIME_WINDOW seconds
Config.DDOS_THRESHOLD           = 1500 # packets per second
Config.DNS_QUERY_SIZE_THRESHOLD = 700  # bytes; larger queries are suspicious
Config.SUSPICIOUS_PORTS         = {4444, 1337, 31337, ...}
Config.KNOWN_MALICIOUS_IPS      = {"x.x.x.x", ...}  # load from threat intel feeds
Config.PHISHING_DOMAINS         = {"example-phish-domain.com", ...}
Config.DATA_EXFIL_THRESHOLD_BYTES = 52428800  # bytes per DATA_EXFIL_TIME_WINDOW
Config.TRAFFIC_ANOMALY_MULTIPLIER = 3.5       # spike factor over baseline
Config.SIEM_OUTPUT_FILE         = "siem/alerts.jsonl"
Config.ALERT_WEBHOOK_URL        = "https://example.local/hook"
```

Optional integration env vars:
- `NSM_ALERT_WEBHOOK_URL`
- `NSM_SLACK_WEBHOOK_URL`
- `NSM_SMTP_HOST`, `NSM_SMTP_PORT`, `NSM_SMTP_USERNAME`, `NSM_SMTP_PASSWORD`
- `NSM_ALERT_EMAIL_FROM`, `NSM_ALERT_EMAIL_TO`
- `NSM_SIEM_OUTPUT_FILE`
- `NSM_PORT_SCAN_TRUSTED_SOURCES` (comma-separated, e.g. `192.168.1.1,10.0.0.10`)

Baseline profiles:
- `dev`
- `office`
- `office_tuned` (reduced anomaly noise from latest simulation baseline)
- `datacenter`
- `home_lab`
- `corp_wifi`
- `server_vlan`

You can load a profile at runtime:

```bash
python main.py --simulate --profile office
python main.py --simulate --profile office_tuned
python main.py --live --profile datacenter --profile-file config_profiles.json
python main.py --live --profile office --live-duration 1800 --save-tuning tuning.json
```

Slack validation:

```bash
set NSM_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
python main.py --simulate --no-dashboard
```

Release-readiness quick check:

```bash
python main.py --simulate --profile office_tuned --no-dashboard --save-tuning tuning-live.json
pytest tests/ -v
```

Deployment hardening assets:
- `deploy/systemd/nsm.service`
- `deploy/windows/install_task.ps1`
- `deploy/windows/run_nsm.ps1`
- `.env.example` for secret/env setup
- `RUNBOOK.md` for incident response workflow

Tip: `Config` auto-loads local `.env` values (if present) before env var reads.

---

## Running Tests

```bash
pytest tests/ -v
```

All 102 tests run without root access or a live network interface.

---

## Sample Output

```
────────────────────────────────────────────────────────────────────────────────
                        🛡  NETWORK SECURITY MONITOR  🛡
                             2026-04-02  20:45:32
────────────────────────────────────────────────────────────────────────────────

  TRAFFIC STATISTICS
  Total packets   : 1,252
  Total bytes     : 158.4 KB
  Packets/sec     : 32,608.1
  TCP / UDP / ICMP: 170 / 1,050 / 0
  DNS / Other     : 32 / 0

  ALERT SUMMARY
  Total alerts    : 6
  Critical / High : 2 / 2
  Medium / Low    : 2 / 0

  RECENT ALERTS
  [HIGH]     [PORT_SCAN]      src=10.0.0.99   Port scan: 20 ports in 10s
  [CRITICAL] [SYN_FLOOD]      src=10.0.99.1   100 SYN packets/s to port 80
  [HIGH]     [BRUTE_FORCE]    src=10.0.99.2   10 attempts on SSH (port 22)
  [MEDIUM]   [DNS_TUNNELING]  src=10.0.99.3   10 oversized DNS queries
  [MEDIUM]   [SUSPICIOUS_PORT] src=10.0.99.4  Connection to port 4444
  [CRITICAL] [DDOS]           src=10.0.99.5   1000 packets/s
```
