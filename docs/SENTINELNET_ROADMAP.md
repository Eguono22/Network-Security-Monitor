# SentinelNet Roadmap

## Phase 1: Foundation (Done/In Progress)
- [x] Core packet detection pipeline
- [x] Alerting integrations (Slack/webhook/email/SIEM file)
- [x] SOC automation playbooks with cooldown
- [x] Vercel API + dashboard pages
- [x] SOC Management dashboard endpoint
- [ ] Persistent datastore for alerts/incidents (currently log-based)

## Phase 2: SOC Operations
- [x] Case management model (`open`, `assigned`, `contained`, `resolved`)
- [x] Analyst assignment and ownership
- [x] MTTR / SLA metrics and trends
- [x] Report export (CSV) for incidents
- [x] Role-based access control for SOC views

## Phase 3: Network & Asset Context
- [x] Device inventory service (IP/MAC/vendor/OS/risk/open ports)
- [ ] Network topology and zone mapping
- [ ] Baseline per subnet/segment profiles
- [x] Unauthorized device detection and lifecycle

## Phase 4: Threat Intelligence & Enrichment
- [ ] AbuseIPDB enrichment adapter
- [ ] AlienVault OTX feed adapter
- [ ] VirusTotal/Shodan lookup hooks
- [ ] ATT&CK mapping for alert-to-technique
- [ ] IOC watchlist management UI/API

## Phase 5: OT/Industrial Security
- [ ] Modbus/TCP parser and anomaly rules
- [ ] PLC asset inventory and role tagging
- [ ] SCADA flow monitoring and policy alerts
- [ ] Engineering workstation access watch rules
- [ ] Segment boundary policy checks for OT zones

## Phase 6: Multi-Tenant + Commercialization
- [ ] Tenant isolation and scoped data access
- [ ] MSP tenant management and billing hooks
- [ ] Plan limits (free/pro/enterprise)
- [ ] White-label and API key management

## Immediate Next Sprint (Recommended)
- [x] Add incident case object + local persistence (`incidents.db`)
- [x] Add `/api/incidents` + `/soc-management` incident table
- [x] Add CSV incident export endpoint
- [x] Add alert-to-case auto-link from SOC automation actions
- [x] Add basic threat-intel enrichment mock endpoint
- [x] Add one OT detector stub (`modbus_command_spike`) with tests
- [x] Add role-aware SOC access controls
