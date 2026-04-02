# Network Security Monitor

A Network Security Monitor (NSM) that continuously observes, analyzes, and detects suspicious activity across a network. It identifies cyber threats such as port scans, SYN floods, brute-force login attempts, DDoS attacks, DNS tunneling, connections to back-door ports, and traffic to/from known-malicious IP addresses.

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

---

## Project Structure

```
network_security_monitor/
├── __init__.py          – Public API re-exports
├── config.py            – Configurable thresholds and settings
├── models.py            – Data classes: Packet, Alert, TrafficStats
├── packet_analyzer.py   – Scapy → Packet conversion
├── threat_detector.py   – All detection logic (7 detectors)
├── alert_manager.py     – Alert storage, logging, and callbacks
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

### Live Capture (requires root / CAP_NET_RAW)

```bash
sudo python main.py --live
sudo python main.py --live --interface eth0
```

### View Past Alerts

```bash
python main.py --show-alerts alerts.log
```

---

## Configuration

Edit `network_security_monitor/config.py` to adjust detection thresholds.  
Key settings:

```python
Config.PORT_SCAN_THRESHOLD      = 20   # distinct ports in PORT_SCAN_TIME_WINDOW seconds
Config.SYN_FLOOD_THRESHOLD      = 100  # SYN packets per second
Config.BRUTE_FORCE_THRESHOLD    = 10   # attempts per BRUTE_FORCE_TIME_WINDOW seconds
Config.DDOS_THRESHOLD           = 1000 # packets per second
Config.DNS_QUERY_SIZE_THRESHOLD = 512  # bytes; larger queries are suspicious
Config.SUSPICIOUS_PORTS         = {4444, 1337, 31337, ...}
Config.KNOWN_MALICIOUS_IPS      = {"x.x.x.x", ...}  # load from threat intel feeds
```

---

## Running Tests

```bash
pytest tests/ -v
```

All 91 tests run without root access or a live network interface.

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
