---
name: application-performance-performance-optimization
description: Optimize end-to-end application performance with profiling, observability, and backend/frontend tuning. Use when coordinating performance optimization across the stack. 
category: Document Processing
source: antigravity
tags: [javascript, react, api, ai, agent, workflow, design, document, image, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/application-performance-performance-optimization
---


Optimize application performance end-to-end using specialized performance and optimization agents:

[Extended thinking: This workflow orchestrates a comprehensive performance optimization process across the entire application stack. Starting with deep profiling and baseline establishment, the workflow progresses through targeted optimizations in each system layer, validates improvements through load testing, and establishes continuous monitoring for sustained performance. Each phase builds on insights from previous phases, creating a data-driven optimization strategy that addresses real bottlenecks rather than theoretical improvements. The workflow emphasizes modern observability practices, user-centric performance metrics, and cost-effective optimization strategies.]

## Use this skill when

- Coordinating performance optimization across backend, frontend, and infrastructure
- Establishing baselines and profiling to identify bottlenecks
- Designing load tests, performance budgets, or capacity plans
- Building observability for performance and reliability targets

## Do not use this skill when

- The task is a small localized fix with no broader performance goals
- There is no access to metrics, tracing, or profiling data
- The request is unrelated to performance or scalability

## Instructions

1. Confirm performance goals, constraints, and target metrics.
2. Establish baselines with profiling, tracing, and real-user data.
3. Execute phased optimizations across the stack with measurable impact.
4. Validate improvements and set guardrails to prevent regressions.

## Safety

- Avoid load testing production without approvals and safeguards.
- Roll out performance changes gradually with rollback plans.

## Phase 1: Performance Profiling & Baseline

### 1. Comprehensive Performance Profiling

- Use Task tool with subagent_type="performance-engineer"
- Prompt: "Profile application performance comprehensively for: $ARGUMENTS. Generate flame graphs for CPU usage, heap dumps for memory analysis, trace I/O operations, and identify hot paths. Use APM tools like DataDog or New Relic if available. Include database query profiling, API response times, and frontend rendering metrics. Establish performance baselines for all critical user journeys."
- Context: Initial performance investigation
- Output: Detailed performance profile with flame graphs, memory analysis, bottleneck identification, baseline metrics

### 2. Observability Stack Assessment

- Use Task tool with subagent_type="observability-engineer"
- Prompt: "Assess current observability setup for: $ARGUMENTS. Review existing monitoring, distributed tracing with OpenTelemetry, log aggregation, and metrics collection. Identify gaps in visibility, missing metrics, and areas needing better instrumentation. Recommend APM tool integration and custom metrics for business-critical operations."
- Context: Performance profile from step 1
- Output: Observability assessment report, instrumentation gaps, monitoring recommendations

### 3. User Experience Analysis

- Use Task tool with subagent_type="performance-engineer"
- Prompt: "Analyze user experience metrics for: $ARGUMENTS. Measure Core Web Vitals (LCP, FID, CLS), page load times, time to interactive, and perceived performance. Use Real User Monitoring (RUM) data if available. Identify user journeys with poor performance and their business impact."
- Context: Performance baselines from step 1
- Output: UX performance report, Core Web Vitals analysis, user impact assessment

## Phase 2: Database & Backend Optimization

### 4. Database Performance Optimization

- Use Task tool with subagent_type="database-cloud-optimization::database-optimizer"
- Prompt: "Optimize database performance for: $ARGUMENTS based on profiling data: {context_from_phase_1}. Analyze slow query logs, create missing indexes, optimize execution plans, implement query result caching with Redis/Memcached. Review connection pooling, prepared statements, and batch processing opportunities. Consider read replicas and database sharding if needed."
- Context: Performance bottlenecks from phase 1
- Output: Optimized queries, new indexes, caching strategy, connection pool configuration

### 5. Backend Code & API Optimization

- Use Task tool with subagent_type="backend-development::backend-architect"
- Prompt: "Optimize backend services for: $ARGUMENTS targeting bottlenecks: {context_from_phase_1}. Implement efficient algorithms, add application-level caching, optimize N+1 queries, use async/await patterns effectively. Implement pagination, response compression, GraphQL query optimization, and batch API operations. Add circuit breakers and bulkheads for resilience."
- Context: Database optimizations from step 4, profiling data from phase 1
- Output: Optimized backend code, caching implementation, API improvements, resilience patterns

### 6. Microservices & Distributed System Optimization

- Use Task tool with subagent_type="performance-engineer"
- Prompt: "
