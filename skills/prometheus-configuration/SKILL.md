---
name: prometheus-configuration
description: Set up Prometheus for comprehensive metric collection, storage, and monitoring of infrastructure and applications. Use when implementing metrics collection, setting up monitoring infrastructure, or co
category: Document Processing
source: antigravity
tags: [node, api, ai, template, design, document, image, docker, kubernetes, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/prometheus-configuration
---


# Prometheus Configuration

Complete guide to Prometheus setup, metric collection, scrape configuration, and recording rules.

## Do not use this skill when

- The task is unrelated to prometheus configuration
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Purpose

Configure Prometheus for comprehensive metric collection, alerting, and monitoring of infrastructure and applications.

## Use this skill when

- Set up Prometheus monitoring
- Configure metric scraping
- Create recording rules
- Design alert rules
- Implement service discovery

## Prometheus Architecture

```
┌──────────────┐
│ Applications │ ← Instrumented with client libraries
└──────┬───────┘
       │ /metrics endpoint
       ↓
┌──────────────┐
│  Prometheus  │ ← Scrapes metrics periodically
│    Server    │
└──────┬───────┘
       │
       ├─→ AlertManager (alerts)
       ├─→ Grafana (visualization)
       └─→ Long-term storage (Thanos/Cortex)
```

## Installation

### Kubernetes with Helm

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.retention=30d \
  --set prometheus.prometheusSpec.storageVolumeSize=50Gi
```

### Docker Compose

```yaml
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'

volumes:
  prometheus-data:
```

## Configuration File

**prometheus.yml:**
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    region: 'us-west-2'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

# Load rules files
rule_files:
  - /etc/prometheus/rules/*.yml

# Scrape configurations
scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # Node exporters
  - job_name: 'node-exporter'
    static_configs:
      - targets:
        - 'node1:9100'
        - 'node2:9100'
        - 'node3:9100'
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        regex: '([^:]+)(:[0-9]+)?'
        replacement: '${1}'

  # Kubernetes pods with annotations
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
      - source_labels: [__meta_kubernetes_namespace]
        action: replace
        target_label: namespace
      - source_labels: [__meta_kubernetes_pod_name]
        action: replace
        target_label: pod

  # Application metrics
  - job_name: 'my-app'
    static_configs:
      - targets:
        - 'app1.example.com:9090'
        - 'app2.example.com:9090'
    metrics_path: '/metrics'
    scheme: 'https'
    tls_config:
      ca_file: /etc/prometheus/ca.crt
      cert_file: /etc/prometheus/client.crt
      key_file: /etc/prometheus/client.key
```

**Reference:** See `assets/prometheus.yml.template`

## Scrape Configurations

### Static Targets

```yaml
scrape_configs:
  - job_name: 'static-targets'
    static_configs:
      - targets: ['host1:9100', 'host2:9100']
        labels:
          env: 'production'
          region: 'us-west-2'
```

### File-based Service Discovery

```yaml
scrape_configs:
  - job_name: 'file-sd'
    file_sd_configs:
      - files:
        - /etc/prometheus/targets/*.json
        - /etc/prometheus/targets/*.yml
        refresh_interval: 5m
```

**targets/production.json:**
```json
[
  {
    "targets": ["app1:9090", "app2:9090"],
    "labels": {
      "env": "production",
      "service": "api"
    }
  }
]
```

### Kubernetes Service Discovery

```yaml
scrape_configs:
  - job_name: 'kubernetes-services'
    kubernetes_sd_configs:
      - role: service
    relabel_configs:
      - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape]
        action: keep
        regex:
