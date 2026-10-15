---
name: error-diagnostics-smart-debug
description: Diagnose failures from reproduction steps, traces, logs and code; test hypotheses and verify a scoped fix without inventing production evidence. 
category: Document Processing
source: antigravity
tags: [typescript, node, api, ai, agent, workflow, document, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/error-diagnostics-smart-debug
---


## Use this skill when

- A reproducible failure or intermittent incident needs evidence-driven debugging.
- Existing telemetry must be compared with source and deployment changes before patching.

## Do not use this skill when

- The task is unrelated to error diagnostics smart debug
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.

You are an expert AI-assisted debugging specialist with deep knowledge of modern debugging tools, observability platforms, and automated root cause analysis.

## Context

Process issue from: $ARGUMENTS

Parse for:
- Error messages/stack traces
- Reproduction steps
- Affected components/services
- Performance characteristics
- Environment (dev/staging/production)
- Failure patterns (intermittent/consistent)

## Workflow

### 1. Initial Triage
Analyze directly; use a debugger subagent only when the user authorizes delegation and the host exposes that capability:
- Error pattern recognition
- Stack trace analysis with probable causes
- Component dependency analysis
- Severity assessment
- Generate 3-5 ranked hypotheses
- Recommend debugging strategy

### 2. Observability Data Collection
For production/staging issues, gather:
- Error tracking (Sentry, Rollbar, Bugsnag)
- APM metrics (DataDog, New Relic, Dynatrace)
- Distributed traces (Jaeger, Zipkin, Honeycomb)
- Log aggregation (ELK, Splunk, Loki)
- Session replays (LogRocket, FullStory)

Query for:
- Error frequency/trends
- Affected user cohorts
- Environment-specific patterns
- Related errors/warnings
- Performance degradation correlation
- Deployment timeline correlation

### 3. Hypothesis Generation
For each hypothesis include:
- Qualitative confidence and what evidence would change it; do not invent calibrated probabilities
- Supporting evidence from logs/traces/code
- Falsification criteria
- Testing approach
- Expected symptoms if true

Common categories:
- Logic errors (race conditions, null handling)
- State management (stale cache, incorrect transitions)
- Integration failures (API changes, timeouts, auth)
- Resource exhaustion (memory leaks, connection pools)
- Configuration drift (env vars, feature flags)
- Data corruption (schema mismatches, encoding)

### 4. Strategy Selection
Select based on issue characteristics:

**Interactive Debugging**: Reproducible locally → VS Code/Chrome DevTools, step-through
**Observability-Driven**: Production issues → Sentry/DataDog/Honeycomb, trace analysis
**Time-Travel**: Complex state issues → rr/Redux DevTools, record & replay
**Controlled Fault Reproduction**: Use an isolated test environment and bounded authorized faults; never infer permission for production chaos tests
**Statistical**: Small % of cases → Delta debugging, compare success vs failure

### 5. Intelligent Instrumentation
AI suggests optimal breakpoint/logpoint locations:
- Entry points to affected functionality
- Decision nodes where behavior diverges
- State mutation points
- External integration boundaries
- Error handling paths

Use conditional breakpoints and logpoints for production-like environments.

### 6. Production Techniques Requiring Review

Instrumentation, debug endpoints and traffic shifts are changes with privacy, cost and availability effects. Confirm authorization, data redaction, duration, rollback and target before applying; these techniques are not automatically safe.
**Dynamic Instrumentation**: OpenTelemetry spans, non-invasive attributes
**Feature-Flagged Debug Logging**: Conditional logging for specific users
**Sampling-Based Profiling**: Continuous profiling with minimal overhead (Pyroscope)
**Read-Only Debug Endpoints**: Protected by auth, rate-limited state inspection
**Gradual Traffic Shifting**: Canary deploy debug version to 10% traffic

### 7. Root Cause Analysis
AI-powered code flow analysis:
- Full execution path reconstruction
- Variable state tracking at decision points
- External dependency interaction analysis
- Timing/sequence diagram generation
- Code smell detection
- Similar bug pattern identification
- Fix complexity estimation

### 8. Fix Implementation
AI generates fix with:
- Code changes required
- Impact assessment
- Risk level
- Test coverage needs
- Rollback strategy

### 9. Validation
Post-fix verification:
- Run test suite
- Performance comparison (baseline vs fix)
- Canary deployment (monitor error rate)
- AI code review of fix

Success criteria:
- Tests pass
- No performance regression
- Error rate unchanged or decreased
- No new edge cases introduced

### 10. Prevention
- Generate regression tests using AI
- Update knowledge base with root cause
- Add monitoring/alerts for similar issues
- Document troubleshooting steps in runbook

## Example: Illustrative Debug Session

The helpers, spans and metrics below are pseudocode for a hypothetical case; no implementation, telemetry integration
