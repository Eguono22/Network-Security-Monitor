# SentinelNet PRD (Product Requirements)

## Product
- Name: `SentinelNet`
- Tagline: `Real-time network visibility, threat detection, and incident response in one platform.`

## Problem
Small and medium organizations need SOC-grade visibility and response without enterprise tooling cost.

## Goals
- Provide centralized network security monitoring.
- Detect common network and identity attack patterns.
- Automate triage and response playbooks.
- Support SOC workflows (watching, case queues, escalation).
- Support IT + OT/industrial environments.

## Primary Users
- SMB IT administrators
- SOC analysts / SecOps teams
- MSP operators
- Educational institutions
- Industrial/OT security teams

## Core Functional Areas
- Dashboard and SOC management KPIs
- Real-time traffic monitoring and alerting
- Threat detection and anomaly detection
- Log collection and normalization
- Notification routing (Slack/webhook/email/etc.)
- Device inventory and risk scoring
- Incident response automation
- Threat intelligence enrichment

## Current Implementation Baseline (This Repo)
- Threat detection pipeline in Python (`ThreatDetector`)
- Alert handling and integrations (`AlertManager`)
- SOC playbook automation (`SOCAutomationEngine`)
- Live monitor + simulation modes (`NetworkMonitor`, `main.py`)
- Vercel serverless UI/API endpoints:
  - `/dashboard`
  - `/network-watcher`
  - `/soc-management`
  - `/api/alerts`, `/api/network-watcher`, `/api/soc-summary`

## Next Capability Targets
- Multi-source log ingestion (syslog/Windows/cloud)
- Device inventory service (MAC, OS, vendor, risk)
- Analyst case lifecycle (open/assign/resolve/SLA)
- Threat intel connectors (AbuseIPDB/OTX/VirusTotal)
- OT protocol inspection (Modbus/TCP, SCADA telemetry)
- Multi-tenant controls for MSP mode

## Non-Functional Requirements
- Clear severity model (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- Action audit trail for every automation step (JSONL/API)
- Runtime configurability via env/profile
- Low-noise operation with tunable thresholds/cooldowns
- Operator-safe defaults (no destructive auto-containment by default)

## Suggested Stack (Target State)
- Frontend: React/Next.js + charts
- Backend API: Python FastAPI (or Node + Python hybrid)
- Data: PostgreSQL + document/event store + Redis
- Detection engines: native + Suricata/Zeek integration
- Deployment: containers on VM/Kubernetes (not serverless for live sniffing)
