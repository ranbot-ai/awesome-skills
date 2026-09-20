---
name: ai-sre-incident-response
description: Build AI-focused SRE incident response practices for LLM outages, degraded quality, runaway cost events, and safety regressions. 
category: AI & Agents
source: antigravity
tags: [python, markdown, api, ai, agent, llm, gpt, template, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-sre-incident-response
---


# AI SRE Incident Response

Apply SRE rigor to AI systems where incidents include quality regressions, unsafe outputs, and budget explosions.

## When to Use This Skill

- An LLM endpoint begins returning degraded or hallucinated answers
- Token spend spikes beyond budget thresholds
- A model provider goes down and traffic must fail over
- Safety guardrails fire at abnormal rates
- A new model deployment causes latency or accuracy regression

## Prerequisites

- Prometheus and Alertmanager deployed with scrape targets for AI services
- Grafana dashboards for golden signals (latency, error rate, cost, quality)
- On-call rotation configured in PagerDuty, Opsgenie, or equivalent
- Runbook repository accessible to responders
- Rollback mechanism for model and prompt versions (GitOps or feature flags)

## AI Incident Classes

- **Availability incident**: model/provider unavailable, timeout storm.
- **Quality incident**: answer accuracy or tool success drops below SLO.
- **Safety incident**: harmful or policy-violating outputs increase.
- **Cost incident**: unexpected token or provider spend spike.

## Severity Framework

| Severity | Criteria | Response Time | Notification |
|----------|----------|---------------|--------------|
| SEV1 | User-facing outage, compliance risk, data leak | 5 min | Page on-call + incident commander |
| SEV2 | Major degradation in key flows | 15 min | Page on-call |
| SEV3 | Limited impact or internal-only issue | 1 hour | Slack alert |
| SEV4 | Cosmetic or low-priority regression | Next business day | Ticket |

## Golden Signals for AI Services

- Request success rate
- Latency (queue + generation + tool execution)
- Hallucination/groundedness proxy metrics
- Cost per minute and per tenant
- Guardrail violation rate

## Prometheus Alert Rules

```yaml
# prometheus-ai-alerts.yaml
groups:
  - name: ai-service-alerts
    rules:
      - alert: ModelEndpointDown
        expr: up{job="llm-inference"} == 0
        for: 2m
        labels:
          severity: sev1
        annotations:
          summary: "LLM inference endpoint {{ $labels.instance }} is down"
          runbook_url: "https://runbooks.internal/ai/model-outage"

      - alert: HighHallucinationRate
        expr: |
          rate(llm_hallucination_detected_total[10m])
          / rate(llm_requests_total[10m]) > 0.15
        for: 5m
        labels:
          severity: sev2
        annotations:
          summary: "Hallucination rate above 15% for {{ $labels.model }}"
          runbook_url: "https://runbooks.internal/ai/quality-regression"

      - alert: TokenCostExplosion
        expr: |
          sum(rate(llm_token_cost_dollars[5m])) by (tenant)
          > 0.50
        for: 3m
        labels:
          severity: sev2
        annotations:
          summary: "Token spend exceeds $0.50/min for tenant {{ $labels.tenant }}"
          runbook_url: "https://runbooks.internal/ai/cost-spike"

      - alert: LatencyP95Exceeded
        expr: |
          histogram_quantile(0.95,
            rate(llm_request_duration_seconds_bucket[5m])
          ) > 5
        for: 5m
        labels:
          severity: sev2
        annotations:
          summary: "LLM p95 latency exceeds 5s for {{ $labels.service }}"

      - alert: GuardrailViolationSpike
        expr: |
          rate(llm_guardrail_violations_total[10m])
          / rate(llm_requests_total[10m]) > 0.05
        for: 5m
        labels:
          severity: sev1
        annotations:
          summary: "Guardrail violations above 5% for {{ $labels.model }}"
          runbook_url: "https://runbooks.internal/ai/safety-incident"

      - alert: ModelQualityDrop
        expr: |
          llm_eval_score{metric="groundedness"} < 0.70
        for: 10m
        labels:
          severity: sev2
        annotations:
          summary: "Groundedness score dropped below 0.70 for {{ $labels.model }}"

      - alert: ProviderErrorRateHigh
        expr: |
          rate(llm_provider_errors_total[5m])
          / rate(llm_provider_requests_total[5m]) > 0.10
        for: 3m
        labels:
          severity: sev2
        annotations:
          summary: "Provider {{ $labels.provider }} error rate above 10%"
```

## Response Playbooks

### Model Outage Runbook

```text
TRIGGER: ModelEndpointDown fires for > 2 minutes
RESPONDER: On-call AI platform engineer

1. Acknowledge alert in PagerDuty.
2. Check provider status page (e.g., status.openai.com).
3. Verify network connectivity:
     curl -s -o /dev/null -w "%{http_code}" https://api.provider.com/health
4. If provider is down:
     a. Enable fallback model route in gateway config.
     b. kubectl set env deployment/llm-gateway FALLBACK_ENABLED=true
     c. Verify fallback traffic is flowing via Grafana dashboard.
5. If self-hosted model is down:
     a. Check pod status: kubectl get pods -l app=llm-inference -n ai
     b. Check GPU health: kubectl logs -l app=llm-inference --tail=50
     c. Restart if OOM: kubectl rollout restart deployment/llm-inference -n ai
6
