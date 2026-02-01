---
name: service-mesh-observability
description: Implement comprehensive observability for service meshes including distributed tracing, metrics, and visualization. Use when setting up mesh monitoring, debugging latency issues, or implementing SLOs 
category: Creative & Media
source: antigravity
tags: [node, api, ai, template, image, kubernetes, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/service-mesh-observability
---


# Service Mesh Observability

Complete guide to observability patterns for Istio, Linkerd, and service mesh deployments.

## Do not use this skill when

- The task is unrelated to service mesh observability
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Setting up distributed tracing across services
- Implementing service mesh metrics and dashboards
- Debugging latency and error issues
- Defining SLOs for service communication
- Visualizing service dependencies
- Troubleshooting mesh connectivity

## Core Concepts

### 1. Three Pillars of Observability

```
┌─────────────────────────────────────────────────────┐
│                  Observability                       │
├─────────────────┬─────────────────┬─────────────────┤
│     Metrics     │     Traces      │      Logs       │
│                 │                 │                 │
│ • Request rate  │ • Span context  │ • Access logs   │
│ • Error rate    │ • Latency       │ • Error details │
│ • Latency P50   │ • Dependencies  │ • Debug info    │
│ • Saturation    │ • Bottlenecks   │ • Audit trail   │
└─────────────────┴─────────────────┴─────────────────┘
```

### 2. Golden Signals for Mesh

| Signal | Description | Alert Threshold |
|--------|-------------|-----------------|
| **Latency** | Request duration P50, P99 | P99 > 500ms |
| **Traffic** | Requests per second | Anomaly detection |
| **Errors** | 5xx error rate | > 1% |
| **Saturation** | Resource utilization | > 80% |

## Templates

### Template 1: Istio with Prometheus & Grafana

```yaml
# Install Prometheus
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus
  namespace: istio-system
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    scrape_configs:
      - job_name: 'istio-mesh'
        kubernetes_sd_configs:
          - role: endpoints
            namespaces:
              names:
                - istio-system
        relabel_configs:
          - source_labels: [__meta_kubernetes_service_name]
            action: keep
            regex: istio-telemetry
---
# ServiceMonitor for Prometheus Operator
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: istio-mesh
  namespace: istio-system
spec:
  selector:
    matchLabels:
      app: istiod
  endpoints:
    - port: http-monitoring
      interval: 15s
```

### Template 2: Key Istio Metrics Queries

```promql
# Request rate by service
sum(rate(istio_requests_total{reporter="destination"}[5m])) by (destination_service_name)

# Error rate (5xx)
sum(rate(istio_requests_total{reporter="destination", response_code=~"5.."}[5m]))
  / sum(rate(istio_requests_total{reporter="destination"}[5m])) * 100

# P99 latency
histogram_quantile(0.99,
  sum(rate(istio_request_duration_milliseconds_bucket{reporter="destination"}[5m]))
  by (le, destination_service_name))

# TCP connections
sum(istio_tcp_connections_opened_total{reporter="destination"}) by (destination_service_name)

# Request size
histogram_quantile(0.99,
  sum(rate(istio_request_bytes_bucket{reporter="destination"}[5m]))
  by (le, destination_service_name))
```

### Template 3: Jaeger Distributed Tracing

```yaml
# Jaeger installation for Istio
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    enableTracing: true
    defaultConfig:
      tracing:
        sampling: 100.0  # 100% in dev, lower in prod
        zipkin:
          address: jaeger-collector.istio-system:9411
---
# Jaeger deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger
  namespace: istio-system
spec:
  selector:
    matchLabels:
      app: jaeger
  template:
    metadata:
      labels:
        app: jaeger
    spec:
      containers:
        - name: jaeger
          image: jaegertracing/all-in-one:1.50
          ports:
            - containerPort: 5775   # UDP
            - containerPort: 6831   # Thrift
            - containerPort: 6832   # Thrift
            - containerPort: 5778   # Config
            - containerPort: 16686  # UI
            - containerPort: 14268  # HTTP
            - containerPort: 14250  # gRPC
            - containerPort: 9411   # Zipkin
          env:
            - name: COLLECTOR_ZIPKIN_HOST_PORT
              value: ":9411"
```

### Template 4: Linkerd Viz Dashboard

```bash
# Install Linkerd viz extension
linkerd viz install | kubectl apply -f -

# Access dashboard
linkerd viz dashboard

# CLI commands for observability
# Top requests
linkerd viz top deploy/my-app

# Per-route metrics
linkerd viz routes deploy/my-app --to deploy/backend

# Live traffic inspection
linkerd viz tap deploy/my-app --to deploy/backend

# Service edges (dependencies)
linkerd viz edges deployment -n my-namespace
```

### Template 5: Grafana Dashboard JSO
