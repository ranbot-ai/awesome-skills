---
name: patterns
description: Reference document for monopoly patterns. 
category: AI & Agents
source: antigravity
tags: [react, node, api, ai, workflow, design, document, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/monopoly/patterns
---


# MONOPOLY — Design Patterns Deep Dive

## Table of Contents
1. CQRS
2. Event Sourcing
3. Saga Pattern
4. Circuit Breaker
5. Bulkhead
6. Strangler Fig
7. Sidecar / Service Mesh
8. Outbox Pattern
9. Consistent Hashing
10. Backpressure
11. Leader Election
12. Two-Phase Commit

---

## 1. CQRS (Command Query Responsibility Segregation)

**What it is:** Separate the read model (Query) from the write model (Command) into distinct services, databases, or code paths.

**When to use:**
- Read load is 10×+ write load (most web apps)
- Read queries are complex aggregations over write data
- Need to optimize read and write paths independently
- Domain model is complex (DDD contexts)

**Implementation:**
```
Write Path:  Client → Command API → Write DB (normalized, PostgreSQL)
Read Path:   Client → Query API  → Read DB (denormalized, Redis / Elasticsearch)
Sync:        Write DB → CDC (Debezium) → Message Queue → Read DB updater
```

**Trade-offs:**
- ✅ Independent scaling of read and write
- ✅ Optimized schemas for each operation type
- ❌ Eventual consistency between write and read models
- ❌ Increased complexity; two models to maintain

**Real-world users:** Amazon (order service), LinkedIn (feed)

---

## 2. Event Sourcing

**What it is:** Store state as a sequence of immutable events rather than current state. Rebuild current state by replaying events.

**When to use:**
- Full audit trail is a regulatory requirement (fintech, healthcare)
- Need to replay history for debugging or analytics
- Complex domain with many state transitions
- Need to derive multiple read projections from same data

**Implementation:**
```
Event Store: append-only log (Kafka, EventStoreDB)
Snapshots:   periodic snapshots to speed up state rebuild
Projections: consumers build read models from events
```

**Trade-offs:**
- ✅ Complete audit history; perfect for compliance
- ✅ Replay and time-travel debugging
- ❌ Querying current state requires projection maintenance
- ❌ Event schema evolution is hard
- ❌ High storage overhead over time

---

## 3. Saga Pattern

**What it is:** Manage distributed transactions across microservices via a sequence of local transactions, each publishing an event. If a step fails, compensating transactions undo previous steps.

**Two variants:**
- **Choreography:** Services react to events autonomously (decentralized)
- **Orchestration:** A central Saga Orchestrator coordinates steps (centralized)

**When to use:**
- Multi-service workflows where ACID across services is impossible
- Long-running business transactions (order → payment → inventory → shipping)
- Need rollback across service boundaries

**Choreography Example:**
```
OrderService creates order →
  [event: OrderCreated] →
    PaymentService charges card →
      [event: PaymentProcessed] →
        InventoryService reserves stock →
          [event: StockReserved] →
            ShippingService books courier
```

**Compensating Transactions (on failure):**
```
ShippingService fails →
  [event: ShippingFailed] →
    InventoryService releases stock →
      PaymentService refunds card →
        OrderService marks order failed
```

**Trade-offs:**
- ✅ No distributed locking; high availability
- ✅ Scales well across services
- ❌ Hard to debug; distributed trace required
- ❌ Compensating transactions are complex to implement correctly

---

## 4. Circuit Breaker

**What it is:** A proxy that monitors calls to a service. If failure rate exceeds threshold, the circuit "opens" and calls fail fast instead of waiting for timeout.

**States:**
```
CLOSED  → calls pass through; monitor failure rate
OPEN    → calls fail immediately; no calls to downstream
HALF-OPEN → let a probe call through; if success, close; if fail, stay open
```

**When to use:**
- Calling any external service (payment gateway, SMS, email)
- Microservices calling each other
- Preventing timeout cascade when downstream is slow

**Implementation tools:** Hystrix (deprecated), Resilience4j, Polly (.NET), Envoy proxy

**Thresholds (starting point):**
- Open after 50% failure rate over 10 requests
- Stay open for 30 seconds
- Half-open: allow 1 probe request

**Trade-offs:**
- ✅ Prevents cascade failures
- ✅ Gives downstream time to recover
- ❌ Adds latency overhead for monitoring
- ❌ Requires fallback behavior when circuit is open

---

## 5. Bulkhead

**What it is:** Isolate components so a failure in one doesn't consume resources of others. Named after the watertight compartments in ship hulls.

**Types:**
- **Thread Pool Bulkhead:** Separate thread pools per service call
- **Semaphore Bulkhead:** Limit concurrent calls per service
- **Process Bulkhead:** Separate processes/containers per service type

**When to use:**
- Multiple tenants sharing infrastructure (SaaS)
- One slow service consuming all connection pool slots
- Protecting critical services from being starved by non-critical ones

**Example:**
```
Without bulkhead:
  [Recommendation Service hangs] → fills shared thread pool → [Payment Servic
