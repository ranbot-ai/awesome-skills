---
name: mtls-configuration
description: Configure mutual TLS (mTLS) for zero-trust service-to-service communication. Use when implementing zero-trust networking, certificate management, or securing internal service communication. 
category: AI & Agents
source: antigravity
tags: [node, api, ai, agent, template, image, security, kubernetes, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/mtls-configuration
---


# mTLS Configuration

Comprehensive guide to implementing mutual TLS for zero-trust service mesh communication.

## Do not use this skill when

- The task is unrelated to mtls configuration
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Implementing zero-trust networking
- Securing service-to-service communication
- Certificate rotation and management
- Debugging TLS handshake issues
- Compliance requirements (PCI-DSS, HIPAA)
- Multi-cluster secure communication

## Core Concepts

### 1. mTLS Flow

```
┌─────────┐                              ┌─────────┐
│ Service │                              │ Service │
│    A    │                              │    B    │
└────┬────┘                              └────┬────┘
     │                                        │
┌────┴────┐      TLS Handshake          ┌────┴────┐
│  Proxy  │◄───────────────────────────►│  Proxy  │
│(Sidecar)│  1. ClientHello             │(Sidecar)│
│         │  2. ServerHello + Cert      │         │
│         │  3. Client Cert             │         │
│         │  4. Verify Both Certs       │         │
│         │  5. Encrypted Channel       │         │
└─────────┘                              └─────────┘
```

### 2. Certificate Hierarchy

```
Root CA (Self-signed, long-lived)
    │
    ├── Intermediate CA (Cluster-level)
    │       │
    │       ├── Workload Cert (Service A)
    │       └── Workload Cert (Service B)
    │
    └── Intermediate CA (Multi-cluster)
            │
            └── Cross-cluster certs
```

## Templates

### Template 1: Istio mTLS (Strict Mode)

```yaml
# Enable strict mTLS mesh-wide
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
---
# Namespace-level override (permissive for migration)
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: legacy-namespace
spec:
  mtls:
    mode: PERMISSIVE
---
# Workload-specific policy
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: payment-service
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
  mtls:
    mode: STRICT
  portLevelMtls:
    8080:
      mode: STRICT
    9090:
      mode: DISABLE  # Metrics port, no mTLS
```

### Template 2: Istio Destination Rule for mTLS

```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: default
  namespace: istio-system
spec:
  host: "*.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
---
# TLS to external service
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: external-api
spec:
  host: api.external.com
  trafficPolicy:
    tls:
      mode: SIMPLE
      caCertificates: /etc/certs/external-ca.pem
---
# Mutual TLS to external service
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: partner-api
spec:
  host: api.partner.com
  trafficPolicy:
    tls:
      mode: MUTUAL
      clientCertificate: /etc/certs/client.pem
      privateKey: /etc/certs/client-key.pem
      caCertificates: /etc/certs/partner-ca.pem
```

### Template 3: Cert-Manager with Istio

```yaml
# Install cert-manager issuer for Istio
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: istio-ca
spec:
  ca:
    secretName: istio-ca-secret
---
# Create Istio CA secret
apiVersion: v1
kind: Secret
metadata:
  name: istio-ca-secret
  namespace: cert-manager
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-ca-cert>
  tls.key: <base64-encoded-ca-key>
---
# Certificate for workload
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-service-cert
  namespace: my-namespace
spec:
  secretName: my-service-tls
  duration: 24h
  renewBefore: 8h
  issuerRef:
    name: istio-ca
    kind: ClusterIssuer
  commonName: my-service.my-namespace.svc.cluster.local
  dnsNames:
    - my-service
    - my-service.my-namespace
    - my-service.my-namespace.svc
    - my-service.my-namespace.svc.cluster.local
  usages:
    - server auth
    - client auth
```

### Template 4: SPIFFE/SPIRE Integration

```yaml
# SPIRE Server configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-server
  namespace: spire
data:
  server.conf: |
    server {
      bind_address = "0.0.0.0"
      bind_port = "8081"
      trust_domain = "example.org"
      data_dir = "/run/spire/data"
      log_level = "INFO"
      ca_ttl = "168h"
      default_x509_svid_ttl = "1h"
    }

    plugins {
      DataStore "sql" {
        plugin_data {
          database_type = "sqlite3"
          connection_string = "/run/spire/data/datastore.sqlite3"
        }
      }

      NodeAttestor "k8s_psat" {
  
