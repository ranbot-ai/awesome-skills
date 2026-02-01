---
name: backend-development-feature-development
description: Orchestrate end-to-end backend feature development from requirements to deployment. Use when coordinating multi-phase feature delivery across teams and services. 
category: Security & Systems
source: antigravity
tags: [api, ai, agent, workflow, design, document, security, vulnerability, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/backend-development-feature-development
---


Orchestrate end-to-end feature development from requirements to production deployment:

[Extended thinking: This workflow orchestrates specialized agents through comprehensive feature development phases - from discovery and planning through implementation, testing, and deployment. Each phase builds on previous outputs, ensuring coherent feature delivery. The workflow supports multiple development methodologies (traditional, TDD/BDD, DDD), feature complexity levels, and modern deployment strategies including feature flags, gradual rollouts, and observability-first development. Agents receive detailed context from previous phases to maintain consistency and quality throughout the development lifecycle.]

## Use this skill when

- Coordinating end-to-end feature delivery across backend, frontend, and data
- Managing requirements, architecture, implementation, testing, and rollout
- Planning multi-service changes with deployment and monitoring needs
- Aligning teams on scope, risks, and success metrics

## Do not use this skill when

- The task is a small, isolated backend change or bug fix
- You only need a single specialist task, not a full workflow
- There is no deployment or cross-team coordination involved

## Instructions

1. Confirm feature scope, success metrics, and constraints.
2. Select a methodology and define phase outputs.
3. Orchestrate implementation, testing, and security validation.
4. Prepare rollout, monitoring, and documentation plans.

## Safety

- Avoid production changes without approvals and rollback plans.
- Validate data migrations and feature flags in staging first.

## Configuration Options

### Development Methodology

- **traditional**: Sequential development with testing after implementation
- **tdd**: Test-Driven Development with red-green-refactor cycles
- **bdd**: Behavior-Driven Development with scenario-based testing
- **ddd**: Domain-Driven Design with bounded contexts and aggregates

### Feature Complexity

- **simple**: Single service, minimal integration (1-2 days)
- **medium**: Multiple services, moderate integration (3-5 days)
- **complex**: Cross-domain, extensive integration (1-2 weeks)
- **epic**: Major architectural changes, multiple teams (2+ weeks)

### Deployment Strategy

- **direct**: Immediate rollout to all users
- **canary**: Gradual rollout starting with 5% of traffic
- **feature-flag**: Controlled activation via feature toggles
- **blue-green**: Zero-downtime deployment with instant rollback
- **a-b-test**: Split traffic for experimentation and metrics

## Phase 1: Discovery & Requirements Planning

1. **Business Analysis & Requirements**
   - Use Task tool with subagent_type="business-analytics::business-analyst"
   - Prompt: "Analyze feature requirements for: $ARGUMENTS. Define user stories, acceptance criteria, success metrics, and business value. Identify stakeholders, dependencies, and risks. Create feature specification document with clear scope boundaries."
   - Expected output: Requirements document with user stories, success metrics, risk assessment
   - Context: Initial feature request and business context

2. **Technical Architecture Design**
   - Use Task tool with subagent_type="comprehensive-review::architect-review"
   - Prompt: "Design technical architecture for feature: $ARGUMENTS. Using requirements: [include business analysis from step 1]. Define service boundaries, API contracts, data models, integration points, and technology stack. Consider scalability, performance, and security requirements."
   - Expected output: Technical design document with architecture diagrams, API specifications, data models
   - Context: Business requirements, existing system architecture

3. **Feasibility & Risk Assessment**
   - Use Task tool with subagent_type="security-scanning::security-auditor"
   - Prompt: "Assess security implications and risks for feature: $ARGUMENTS. Review architecture: [include technical design from step 2]. Identify security requirements, compliance needs, data privacy concerns, and potential vulnerabilities."
   - Expected output: Security assessment with risk matrix, compliance checklist, mitigation strategies
   - Context: Technical design, regulatory requirements

## Phase 2: Implementation & Development

4. **Backend Services Implementation**
   - Use Task tool with subagent_type="backend-architect"
   - Prompt: "Implement backend services for: $ARGUMENTS. Follow technical design: [include architecture from step 2]. Build RESTful/GraphQL APIs, implement business logic, integrate with data layer, add resilience patterns (circuit breakers, retries), implement caching strategies. Include feature flags for gradual rollout."
   - Expected output: Backend services with APIs, business logic, database integration, feature flags
   - Context: Technical design, API contracts, data models

5. **Frontend Implementation**
   - Use Task tool with subagent_type="frontend-mobile-development::frontend-developer"
   - Prompt: "Build fronten
