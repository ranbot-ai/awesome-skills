---
name: tech-matrix
description: Reference document for monopoly tech-matrix. 
category: Document Processing
source: antigravity
tags: [node, api, ai, workflow, design, document, docker, kubernetes, aws, gcp]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/monopoly/tech-matrix
---


# MONOPOLY — Technology Decision Matrix

## Table of Contents
1. Database Selection
2. Cache Selection
3. Message Queue / Event Streaming
4. API Protocol
5. Search Engine
6. Object Storage
7. Container Orchestration
8. Load Balancer
9. Observability Stack
10. CDN

---

## 1. Database Selection

### Relational (SQL)

| Database | Best For | Avoid When | Scale Ceiling |
|----------|----------|------------|---------------|
| **PostgreSQL** | Complex queries, JSONB, GIS, strong consistency, most default use cases | Ultra-high write throughput (>100K writes/s) | ~10TB single node; use Citus for horizontal |
| **MySQL / MariaDB** | Read-heavy apps, legacy systems, WordPress/Drupal ecosystem | Complex queries, full ACID at scale | ~10TB; use Vitess for sharding |
| **CockroachDB** | Global distributed SQL, geo-partitioning, multi-region | Simple single-region apps (overkill) | Petabyte-scale |
| **PlanetScale** | MySQL-compatible, serverless, branch-based workflow | Complex JOINs (foreign keys removed by design) | Very high — Vitess based |
| **Amazon Aurora** | AWS-native apps, managed PostgreSQL/MySQL, high availability | Non-AWS environments | Up to 128TB, 15 replicas |

### NoSQL

| Database | Best For | Avoid When | Scale Ceiling |
|----------|----------|------------|---------------|
| **MongoDB** | Flexible schema, document model, prototyping | Financial transactions requiring ACID | Petabyte-scale with sharding |
| **DynamoDB** | Key-value at massive scale, AWS-native, serverless, predictable latency | Complex queries, ad-hoc analytics, JOINs | Unlimited (AWS-managed) |
| **Cassandra** | Write-heavy, time-series, wide-column, geographically distributed | Read-heavy with complex queries | Petabyte-scale; used at Apple, Netflix |
| **Redis** | Cache, sessions, leaderboards, pub/sub, rate limiting | Primary data store for complex models | ~1TB per node; cluster for more |
| **Elasticsearch** | Full-text search, log aggregation, analytics | Primary database (durability risk) | Petabyte-scale with clusters |
| **InfluxDB** | Time-series metrics, IoT, monitoring data | General-purpose data | Very high write throughput |
| **Neo4j** | Graph data, social networks, recommendation engines, fraud detection | Non-graph data (overhead not worth it) | Billions of nodes |

### Decision Framework

```
Is your data relational (joins, foreign keys, transactions)?
  YES → Start with PostgreSQL
  NO  → Continue below

Is your primary access pattern key-value?
  YES, need extreme scale → DynamoDB or Cassandra
  YES, need speed/cache → Redis

Is your data document-shaped (nested, flexible schema)?
  YES → MongoDB

Is it time-series (metrics, logs, IoT)?
  YES → InfluxDB or TimescaleDB

Is it graph (relationships are the data)?
  YES → Neo4j

Is it search?
  YES → Elasticsearch / OpenSearch
```

---

## 2. Cache Selection

| Technology | Best For | Max Single Node | Cluster Support |
|------------|----------|----------------|----------------|
| **Redis** | Sessions, leaderboards, pub/sub, complex data structures, Lua scripting | ~1TB RAM | Yes (Redis Cluster, Redis Sentinel) |
| **Memcached** | Simple key-value, multi-threaded, large object cache | ~64GB RAM | Yes (client-side sharding) |
| **Varnish** | HTTP reverse proxy cache, full-page caching | RAM bound | Limited |
| **CloudFront / CDN** | Static assets, edge caching globally | N/A (distributed) | Built-in global distribution |

**Default recommendation: Redis** — more features, better ecosystem, active development.

Use **Memcached** only when: you need multi-threading for CPU-bound caching workloads and don't need data structures beyond string.

---

## 3. Message Queue / Event Streaming

| Technology | Model | Best For | Throughput | Retention |
|------------|-------|----------|------------|-----------|
| **Apache Kafka** | Log-based streaming | Event sourcing, high-throughput pipelines, replay, audit | Millions msg/s | Days to forever |
| **RabbitMQ** | AMQP message broker | Task queues, RPC, routing, fanout | 50K–100K msg/s | Until consumed |
| **AWS SQS** | Managed queue | AWS-native, simple task queue, serverless | Very high (managed) | Up to 14 days |
| **AWS SNS** | Pub/sub notification | Fan-out to many subscribers (email, SMS, Lambda, SQS) | Very high (managed) | No retention |
| **Google Pub/Sub** | Managed streaming | GCP-native, global, serverless | Very high (managed) | Up to 7 days |
| **Redis Pub/Sub** | In-memory pub/sub | Real-time notifications, low latency, fire-and-forget | Very high | None (no retention) |
| **NATS** | Lightweight messaging | IoT, microservices, low latency | Very high | JetStream adds retention |

### Decision Matrix

```
Need event replay / audit trail?
  YES → Kafka or Kinesis

Need simple task queue with retries and DLQ?
  AWS shop → SQS
  Self-hosted → RabbitMQ

Need real-time pub/sub with no persistence?
  Redis Pub/Sub or NATS

Need fan-out to multiple consumers?
  Kafka (consumer groups) or SNS → SQS fan-out

Need < 5 minutes
