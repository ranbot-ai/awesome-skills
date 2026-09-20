---
name: alerting-oncall
description: Set up alerting rules, configure on-call rotations, and manage incident response workflows. 
category: Document Processing
source: antigravity
tags: [markdown, api, ai, agent, workflow, template, design, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/alerting-oncall
---


# Alerting & On-Call

Configure effective alerting and on-call management for production systems.

## Prerequisites

- Monitoring system (Prometheus, Datadog, etc.)
- On-call platform (PagerDuty, Opsgenie, Grafana OnCall)
- Communication channels (Slack, email)

## Alerting Best Practices

### Alert Categories

```yaml
# Severity levels
critical:
  - Service completely down
  - Data loss imminent
  - Security breach
  response: Immediate page, wake people up

high:
  - Service degraded significantly
  - Error rate above SLO
  - Capacity near limit
  response: Page during business hours, notify after hours

medium:
  - Performance degradation
  - Non-critical component failure
  - Warning thresholds exceeded
  response: Notify via Slack, review next business day

low:
  - Informational alerts
  - Capacity planning triggers
  - Routine maintenance needed
  response: Email notification, weekly review
```

### Alert Design Principles

```yaml
# Good alert characteristics
alerts:
  actionable:
    - Every alert should require human action
    - Include runbook links
    - Clear remediation steps

  relevant:
    - Alert on symptoms, not causes
    - Focus on user impact
    - Avoid alerting on expected behavior

  timely:
    - Appropriate thresholds
    - Suitable evaluation windows
    - Account for normal variance

  unique:
    - No duplicate alerts
    - Proper alert grouping
    - Clear ownership
```

## Prometheus Alerting

### Alert Rules

```yaml
# prometheus/rules/alerts.yml
groups:
  - name: service_alerts
    rules:
      # High-level service health
      - alert: ServiceDown
        expr: up{job="myapp"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.instance }} is down"
          description: "{{ $labels.job }} on {{ $labels.instance }} has been down for more than 1 minute."
          runbook_url: "https://wiki.example.com/runbooks/service-down"

      # Error rate alert
      - alert: HighErrorRate
        expr: |
          sum(rate(http_requests_total{status=~"5.."}[5m])) by (service)
          / sum(rate(http_requests_total[5m])) by (service) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate for {{ $labels.service }}"
          description: "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes"

      # Latency alert (SLO-based)
      - alert: HighLatency
        expr: |
          histogram_quantile(0.95, 
            sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service)
          ) > 0.5
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "P95 latency above 500ms for {{ $labels.service }}"
```

### Alertmanager Configuration

```yaml
# alertmanager.yml
global:
  resolve_timeout: 5m
  slack_api_url: 'https://hooks.slack.com/services/xxx'
  pagerduty_url: 'https://events.pagerduty.com/v2/enqueue'

templates:
  - '/etc/alertmanager/templates/*.tmpl'

route:
  receiver: 'default-receiver'
  group_by: ['alertname', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  
  routes:
    # Critical alerts go to PagerDuty
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
      group_wait: 0s
      repeat_interval: 1h

    # High severity during business hours
    - match:
        severity: high
      receiver: 'slack-high'
      active_time_intervals:
        - business-hours

    # Route by team
    - match_re:
        team: platform.*
      receiver: 'platform-team'

receivers:
  - name: 'default-receiver'
    slack_configs:
      - channel: '#alerts'
        send_resolved: true

  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: 'xxx'
        severity: critical
        description: '{{ .CommonAnnotations.summary }}'
        details:
          firing: '{{ template "pagerduty.firing" . }}'

  - name: 'slack-high'
    slack_configs:
      - channel: '#alerts-high'
        title: '{{ .CommonAnnotations.summary }}'
        text: '{{ .CommonAnnotations.description }}'
        actions:
          - type: button
            text: 'Runbook'
            url: '{{ .CommonAnnotations.runbook_url }}'
          - type: button
            text: 'Dashboard'
            url: '{{ .CommonAnnotations.dashboard_url }}'

  - name: 'platform-team'
    slack_configs:
      - channel: '#platform-alerts'

time_intervals:
  - name: business-hours
    time_intervals:
      - weekdays: ['monday:friday']
        times:
          - start_time: '09:00'
            end_time: '17:00'

inhibit_rules:
  - source_match:
      severity: critical
    target_match:
      severity: high
    equal: ['service']
```

## PagerDuty Integration

### Service Configuration

```yaml
# Terraform example
resource "pagerduty_service" "myapp" {
  name                    = "MyApp Production"
  description             = "Production application service"
  escala
