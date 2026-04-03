# NSM Incident Runbook

## 1. Alert Intake
- Confirm alert source: dashboard, log file, Slack/webhook, or SIEM stream.
- Record: timestamp, threat type, severity, `src_ip`, `dst_ip`, `dst_port`, and metadata.
- De-duplicate repeating alerts from the same source over a short window.

## 2. Triage
- `PORT_SCAN`: verify if source is approved scanner/vulnerability tooling.
- `BRUTE_FORCE`: check target host auth logs (SSH/RDP/etc.) and account lockouts.
- `SYN_FLOOD` / `DDOS`: compare with edge firewall/load balancer counters.
- `DNS_TUNNELING`: inspect queried domains and payload sizes.
- `PHISHING_ATTEMPT`: extract IOC domain/URL and search endpoint/email logs.
- `DATA_EXFILTRATION`: validate if upload is expected backup or sanctioned transfer.
- `SUSPICIOUS_PORT` / `MALICIOUS_IP`: correlate with threat intel and EDR telemetry.
- `UNUSUAL_TRAFFIC`: compare with expected change windows or deployments.

## 3. Containment
- Block malicious source IPs at firewall/ACL when confidence is high.
- Isolate compromised hosts (quarantine VLAN/EDR isolate).
- Disable compromised credentials and force resets.
- Add temporary WAF/rate-limit rules for volumetric attacks.

## 4. Eradication and Recovery
- Remove malware, persistence, unauthorized users, and rogue services.
- Patch exploited vulnerabilities and rotate exposed credentials/keys.
- Restore normal network routing/policies gradually and monitor regression.

## 5. Evidence and Communication
- Preserve artifacts: NSM alerts, packet captures, host logs, firewall events.
- Maintain timeline of detection, response actions, and decisions.
- Notify stakeholders per severity SLA.

## 6. Post-Incident Tuning
- Run baseline/tuning output:
  - `python main.py --simulate --profile office --save-tuning tuning.json`
  - `python main.py --live --profile office --live-duration 1800 --save-tuning tuning.json`
- Apply recommended overrides to `config_profiles.json`.
- Re-run baseline and verify lower false positives without losing detections.
