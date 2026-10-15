---
name: ai-inference-service-mesh
description: Use verified service mesh patterns for AI inference traffic management, mTLS, canary releases, policy enforcement, and cross-cluster resilience. 
category: AI & Agents
source: antigravity
tags: [api, ai, agent, llm, template, design, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-inference-service-mesh
---


# AI Inference Service Mesh

Apply Istio/Linkerd mesh controls to secure and optimize east-west AI traffic across inference microservices.

## Why Mesh for AI

- Enforce mTLS between gateway, retriever, reranker, and model services
- Apply fine-grained traffic policies without app code changes
- Run progressive delivery for model-serving backends
- Observe latency hops for retrieval + generation chains
- Route inference requests by model version, tenant, or priority tier
- Protect expensive GPU-backed services from cascading failures

## Prerequisites

Confirm the exact cluster/context, mesh version, CRD schemas, owned namespace and authorized mutation scope. Examples are alternative fragments, not a manifest to apply wholesale: multiple DestinationRules for the same host must be consolidated under the installed version's merge rules. Preview and validate in a disposable environment; protect production routes and rollback evidence.


```bash
# Illustrative mutating install; default is not a validated production configuration
istioctl install --set profile=default \
  --set meshConfig.accessLogFile=/dev/stdout \
  --set meshConfig.defaultConfig.holdApplicationUntilProxyStarts=true

# Label inference namespace for sidecar injection
kubectl create namespace ai-inference
kubectl label namespace ai-inference istio-injection=enabled

# Verify installation
istioctl verify-install
istioctl analyze -n ai-inference
```

## Core Patterns

### mTLS Strict Mode Cluster-Wide

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
---
# Namespace-level override if needed for gradual rollout
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: ai-inference-mtls
  namespace: ai-inference
spec:
  mtls:
    mode: STRICT
  portLevelMtls:
    # gRPC inference port
    8081:
      mode: STRICT
    # Prometheus metrics port - allow plaintext scraping
    9090:
      mode: PERMISSIVE
```

### AuthorizationPolicy Per Service Account

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: model-server-access
  namespace: ai-inference
spec:
  selector:
    matchLabels:
      app: model-server
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
        - "cluster.local/ns/ai-inference/sa/api-gateway"
        - "cluster.local/ns/ai-inference/sa/orchestrator"
    to:
    - operation:
        methods: ["POST"]
        paths: ["/v1/predict", "/v1/embeddings", "/v2/models/*/infer"]
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-external-to-retriever
  namespace: ai-inference
spec:
  selector:
    matchLabels:
      app: vector-retriever
  action: DENY
  rules:
  - from:
    - source:
        notNamespaces: ["ai-inference"]
```

### Egress Policy for Approved Model Endpoints

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: openai-api
  namespace: ai-inference
spec:
  hosts:
  - api.openai.com
  ports:
  - number: 443
    name: https
    protocol: TLS
  resolution: DNS
  location: MESH_EXTERNAL

```

A `ServiceEntry` registers a service; it is not a complete egress firewall. Namespace `AuthorizationPolicy` controls requests to selected workloads, not arbitrary outbound HTTPS by destination host. Enforce approved egress through a verified gateway/network policy and test bypass routes. For application-originated HTTPS, do not also originate TLS in a DestinationRule without a designed HTTP-to-TLS route (double TLS breaks the connection).

Official guidance: [Istio egress control](https://istio.io/latest/docs/tasks/traffic-management/egress/egress-control/).

## Traffic Management

### VirtualService for A/B Model Testing

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: model-server
  namespace: ai-inference
spec:
  hosts:
  - model-server
  http:
  # Route by header for explicit model version selection
  - match:
    - headers:
        x-model-version:
          exact: "v2-experimental"
    route:
    - destination:
        host: model-server
        subset: v2-experimental
    timeout: 120s
  # Route by header for A/B test cohort
  - match:
    - headers:
        x-ab-cohort:
          exact: "treatment"
    route:
    - destination:
        host: model-server
        subset: v2-experimental
      weight: 100
    timeout: 120s
  # Default traffic split: 90/10 canary
  - route:
    - destination:
        host: model-server
        subset: v1-stable
      weight: 90
    - destination:
        host: model-server
        subset: v2-experimental
      weight: 10
    timeout: 60s
    retries:
      attempts: 2
      perTryTimeout: 30s
      retryOn: unavailable,resource-exhausted
```

### DestinationRule with Subsets

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: model-server
  namespace: ai-inference
spec:
  h
