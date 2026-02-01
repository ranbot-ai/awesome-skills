---
name: on-call-handoff-patterns
description: Master on-call shift handoffs with context transfer, escalation procedures, and documentation. Use when transitioning on-call responsibilities, documenting shift summaries, or improving on-call proces
category: Document Processing
source: antigravity
tags: [node, markdown, api, ai, template, document, security, kubernetes, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/on-call-handoff-patterns
---


# On-Call Handoff Patterns

Effective patterns for on-call shift transitions, ensuring continuity, context transfer, and reliable incident response across shifts.

## Do not use this skill when

- The task is unrelated to on-call handoff patterns
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Transitioning on-call responsibilities
- Writing shift handoff summaries
- Documenting ongoing investigations
- Establishing on-call rotation procedures
- Improving handoff quality
- Onboarding new on-call engineers

## Core Concepts

### 1. Handoff Components

| Component | Purpose |
|-----------|---------|
| **Active Incidents** | What's currently broken |
| **Ongoing Investigations** | Issues being debugged |
| **Recent Changes** | Deployments, configs |
| **Known Issues** | Workarounds in place |
| **Upcoming Events** | Maintenance, releases |

### 2. Handoff Timing

```
Recommended: 30 min overlap between shifts

Outgoing:
├── 15 min: Write handoff document
└── 15 min: Sync call with incoming

Incoming:
├── 15 min: Review handoff document
├── 15 min: Sync call with outgoing
└── 5 min: Verify alerting setup
```

## Templates

### Template 1: Shift Handoff Document

```markdown
# On-Call Handoff: Platform Team

**Outgoing**: @alice (2024-01-15 to 2024-01-22)
**Incoming**: @bob (2024-01-22 to 2024-01-29)
**Handoff Time**: 2024-01-22 09:00 UTC

---

## 🔴 Active Incidents

### None currently active
No active incidents at handoff time.

---

## 🟡 Ongoing Investigations

### 1. Intermittent API Timeouts (ENG-1234)
**Status**: Investigating
**Started**: 2024-01-20
**Impact**: ~0.1% of requests timing out

**Context**:
- Timeouts correlate with database backup window (02:00-03:00 UTC)
- Suspect backup process causing lock contention
- Added extra logging in PR #567 (deployed 01/21)

**Next Steps**:
- [ ] Review new logs after tonight's backup
- [ ] Consider moving backup window if confirmed

**Resources**:
- Dashboard: [API Latency](https://grafana/d/api-latency)
- Thread: #platform-eng (01/20, 14:32)

---

### 2. Memory Growth in Auth Service (ENG-1235)
**Status**: Monitoring
**Started**: 2024-01-18
**Impact**: None yet (proactive)

**Context**:
- Memory usage growing ~5% per day
- No memory leak found in profiling
- Suspect connection pool not releasing properly

**Next Steps**:
- [ ] Review heap dump from 01/21
- [ ] Consider restart if usage > 80%

**Resources**:
- Dashboard: [Auth Service Memory](https://grafana/d/auth-memory)
- Analysis doc: [Memory Investigation](https://docs/eng-1235)

---

## 🟢 Resolved This Shift

### Payment Service Outage (2024-01-19)
- **Duration**: 23 minutes
- **Root Cause**: Database connection exhaustion
- **Resolution**: Rolled back v2.3.4, increased pool size
- **Postmortem**: [POSTMORTEM-89](https://docs/postmortem-89)
- **Follow-up tickets**: ENG-1230, ENG-1231

---

## 📋 Recent Changes

### Deployments
| Service | Version | Time | Notes |
|---------|---------|------|-------|
| api-gateway | v3.2.1 | 01/21 14:00 | Bug fix for header parsing |
| user-service | v2.8.0 | 01/20 10:00 | New profile features |
| auth-service | v4.1.2 | 01/19 16:00 | Security patch |

### Configuration Changes
- 01/21: Increased API rate limit from 1000 to 1500 RPS
- 01/20: Updated database connection pool max from 50 to 75

### Infrastructure
- 01/20: Added 2 nodes to Kubernetes cluster
- 01/19: Upgraded Redis from 6.2 to 7.0

---

## ⚠️ Known Issues & Workarounds

### 1. Slow Dashboard Loading
**Issue**: Grafana dashboards slow on Monday mornings
**Workaround**: Wait 5 min after 08:00 UTC for cache warm-up
**Ticket**: OPS-456 (P3)

### 2. Flaky Integration Test
**Issue**: `test_payment_flow` fails intermittently in CI
**Workaround**: Re-run failed job (usually passes on retry)
**Ticket**: ENG-1200 (P2)

---

## 📅 Upcoming Events

| Date | Event | Impact | Contact |
|------|-------|--------|---------|
| 01/23 02:00 | Database maintenance | 5 min read-only | @dba-team |
| 01/24 14:00 | Major release v5.0 | Monitor closely | @release-team |
| 01/25 | Marketing campaign | 2x traffic expected | @platform |

---

## 📞 Escalation Reminders

| Issue Type | First Escalation | Second Escalation |
|------------|------------------|-------------------|
| Payment issues | @payments-oncall | @payments-manager |
| Auth issues | @auth-oncall | @security-team |
| Database issues | @dba-team | @infra-manager |
| Unknown/severe | @engineering-manager | @vp-engineering |

---

## 🔧 Quick Reference

### Common Commands
```bash
# Check service health
kubectl get pods -A | grep -v Running

# Recent deployments
kubectl get events --sort-by='.lastTimestamp' | tail -20

# Database connections
psql -c "SELECT count(*) FROM pg_stat_activity;"

#
