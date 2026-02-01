---
name: framework-migration-legacy-modernize
description: Orchestrate a comprehensive legacy system modernization using the strangler fig pattern, enabling gradual replacement of outdated components while maintaining continuous business operations through ex
category: Document Processing
source: antigravity
tags: [python, api, ai, agent, workflow, design, document, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/framework-migration-legacy-modernize
---


# Legacy Code Modernization Workflow

Orchestrate a comprehensive legacy system modernization using the strangler fig pattern, enabling gradual replacement of outdated components while maintaining continuous business operations through expert agent coordination.

[Extended thinking: The strangler fig pattern, named after the tropical fig tree that gradually envelops and replaces its host, represents the gold standard for risk-managed legacy modernization. This workflow implements a systematic approach where new functionality gradually replaces legacy components, allowing both systems to coexist during transition. By orchestrating specialized agents for assessment, testing, security, and implementation, we ensure each migration phase is validated before proceeding, minimizing disruption while maximizing modernization velocity.]

## Use this skill when

- Working on legacy code modernization workflow tasks or workflows
- Needing guidance, best practices, or checklists for legacy code modernization workflow

## Do not use this skill when

- The task is unrelated to legacy code modernization workflow
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Phase 1: Legacy Assessment and Risk Analysis

### 1. Comprehensive Legacy System Analysis
- Use Task tool with subagent_type="legacy-modernizer"
- Prompt: "Analyze the legacy codebase at $ARGUMENTS. Document technical debt inventory including: outdated dependencies, deprecated APIs, security vulnerabilities, performance bottlenecks, and architectural anti-patterns. Generate a modernization readiness report with component complexity scores (1-10), dependency mapping, and database coupling analysis. Identify quick wins vs complex refactoring targets."
- Expected output: Detailed assessment report with risk matrix and modernization priorities

### 2. Dependency and Integration Mapping
- Use Task tool with subagent_type="architect-review"
- Prompt: "Based on the legacy assessment report, create a comprehensive dependency graph showing: internal module dependencies, external service integrations, shared database schemas, and cross-system data flows. Identify integration points that will require facade patterns or adapter layers during migration. Highlight circular dependencies and tight coupling that need resolution."
- Context from previous: Legacy assessment report, component complexity scores
- Expected output: Visual dependency map and integration point catalog

### 3. Business Impact and Risk Assessment
- Use Task tool with subagent_type="business-analytics::business-analyst"
- Prompt: "Evaluate business impact of modernizing each component identified. Create risk assessment matrix considering: business criticality (revenue impact), user traffic patterns, data sensitivity, regulatory requirements, and fallback complexity. Prioritize components using a weighted scoring system: (Business Value × 0.4) + (Technical Risk × 0.3) + (Quick Win Potential × 0.3). Define rollback strategies for each component."
- Context from previous: Component inventory, dependency mapping
- Expected output: Prioritized migration roadmap with risk mitigation strategies

## Phase 2: Test Coverage Establishment

### 1. Legacy Code Test Coverage Analysis
- Use Task tool with subagent_type="unit-testing::test-automator"
- Prompt: "Analyze existing test coverage for legacy components at $ARGUMENTS. Use coverage tools to identify untested code paths, missing integration tests, and absent end-to-end scenarios. For components with <40% coverage, generate characterization tests that capture current behavior without modifying functionality. Create test harness for safe refactoring."
- Expected output: Test coverage report and characterization test suite

### 2. Contract Testing Implementation
- Use Task tool with subagent_type="unit-testing::test-automator"
- Prompt: "Implement contract tests for all integration points identified in dependency mapping. Create consumer-driven contracts for APIs, message queue interactions, and database schemas. Set up contract verification in CI/CD pipeline. Generate performance baselines for response times and throughput to validate modernized components maintain SLAs."
- Context from previous: Integration point catalog, existing test coverage
- Expected output: Contract test suite with performance baselines

### 3. Test Data Management Strategy
- Use Task tool with subagent_type="data-engineering::data-engineer"
- Prompt: "Design test data management strategy for parallel system operation. Create data generation scripts for edge cases, implement data masking for sensitive information, and establish test database refresh procedures. Set up monitoring for data consistency between legacy and modernized component
