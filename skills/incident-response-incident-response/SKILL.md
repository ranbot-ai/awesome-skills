---
name: incident-response-incident-response
description: Use when working with incident response incident response 
category: Security & Systems
source: antigravity
tags: [api, ai, agent, automation, workflow, design, document, security, vulnerability, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/incident-response-incident-response
---


## Use this skill when

- Working on incident response incident response tasks or workflows
- Needing guidance, best practices, or checklists for incident response incident response

## Do not use this skill when

- The task is unrelated to incident response incident response
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

Orchestrate multi-agent incident response with modern SRE practices for rapid resolution and learning:

[Extended thinking: This workflow implements a comprehensive incident command system (ICS) following modern SRE principles. Multiple specialized agents collaborate through defined phases: detection/triage, investigation/mitigation, communication/coordination, and resolution/postmortem. The workflow emphasizes speed without sacrificing accuracy, maintains clear communication channels, and ensures every incident becomes a learning opportunity through blameless postmortems and systematic improvements.]

## Configuration

### Severity Levels
- **P0/SEV-1**: Complete outage, security breach, data loss - immediate all-hands response
- **P1/SEV-2**: Major degradation, significant user impact - rapid response required
- **P2/SEV-3**: Minor degradation, limited impact - standard response
- **P3/SEV-4**: Cosmetic issues, no user impact - scheduled resolution

### Incident Types
- Performance degradation
- Service outage
- Security incident
- Data integrity issue
- Infrastructure failure
- Third-party service disruption

## Phase 1: Detection & Triage

### 1. Incident Detection and Classification
- Use Task tool with subagent_type="incident-responder"
- Prompt: "URGENT: Detect and classify incident: $ARGUMENTS. Analyze alerts from PagerDuty/Opsgenie/monitoring. Determine: 1) Incident severity (P0-P3), 2) Affected services and dependencies, 3) User impact and business risk, 4) Initial incident command structure needed. Check error budgets and SLO violations."
- Output: Severity classification, impact assessment, incident command assignments, SLO status
- Context: Initial alerts, monitoring dashboards, recent changes

### 2. Observability Analysis
- Use Task tool with subagent_type="observability-monitoring::observability-engineer"
- Prompt: "Perform rapid observability sweep for incident: $ARGUMENTS. Query: 1) Distributed tracing (OpenTelemetry/Jaeger), 2) Metrics correlation (Prometheus/Grafana/DataDog), 3) Log aggregation (ELK/Splunk), 4) APM data, 5) Real User Monitoring. Identify anomalies, error patterns, and service degradation points."
- Output: Observability findings, anomaly detection, service health matrix, trace analysis
- Context: Severity level from step 1, affected services

### 3. Initial Mitigation
- Use Task tool with subagent_type="incident-responder"
- Prompt: "Implement immediate mitigation for P$SEVERITY incident: $ARGUMENTS. Actions: 1) Traffic throttling/rerouting if needed, 2) Feature flag disabling for affected features, 3) Circuit breaker activation, 4) Rollback assessment for recent deployments, 5) Scale resources if capacity-related. Prioritize user experience restoration."
- Output: Mitigation actions taken, temporary fixes applied, rollback decisions
- Context: Observability findings, severity classification

## Phase 2: Investigation & Root Cause Analysis

### 4. Deep System Debugging
- Use Task tool with subagent_type="error-debugging::debugger"
- Prompt: "Conduct deep debugging for incident: $ARGUMENTS using observability data. Investigate: 1) Stack traces and error logs, 2) Database query performance and locks, 3) Network latency and timeouts, 4) Memory leaks and CPU spikes, 5) Dependency failures and cascading errors. Apply Five Whys analysis."
- Output: Root cause identification, contributing factors, dependency impact map
- Context: Observability analysis, mitigation status

### 5. Security Assessment
- Use Task tool with subagent_type="security-scanning::security-auditor"
- Prompt: "Assess security implications of incident: $ARGUMENTS. Check: 1) DDoS attack indicators, 2) Authentication/authorization failures, 3) Data exposure risks, 4) Certificate issues, 5) Suspicious access patterns. Review WAF logs, security groups, and audit trails."
- Output: Security assessment, breach analysis, vulnerability identification
- Context: Root cause findings, system logs

### 6. Performance Engineering Analysis
- Use Task tool with subagent_type="application-performance::performance-engineer"
- Prompt: "Analyze performance aspects of incident: $ARGUMENTS. Examine: 1) Resource utilization patterns, 2) Query optimization opportunities, 3) Caching effectiveness, 4) Load balancer health, 5) CDN performance, 6) Autoscaling triggers. Identify bottlenecks and capacity issues."
- Output: Performance bottlenecks, resource reco
