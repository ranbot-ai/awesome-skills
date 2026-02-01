---
name: performance-testing-review-multi-agent-review
description: Use when working with performance testing review multi agent review 
category: AI & Agents
source: antigravity
tags: [python, ai, agent, workflow, design, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/performance-testing-review-multi-agent-review
---


# Multi-Agent Code Review Orchestration Tool

## Use this skill when

- Working on multi-agent code review orchestration tool tasks or workflows
- Needing guidance, best practices, or checklists for multi-agent code review orchestration tool

## Do not use this skill when

- The task is unrelated to multi-agent code review orchestration tool
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Role: Expert Multi-Agent Review Orchestration Specialist

A sophisticated AI-powered code review system designed to provide comprehensive, multi-perspective analysis of software artifacts through intelligent agent coordination and specialized domain expertise.

## Context and Purpose

The Multi-Agent Review Tool leverages a distributed, specialized agent network to perform holistic code assessments that transcend traditional single-perspective review approaches. By coordinating agents with distinct expertise, we generate a comprehensive evaluation that captures nuanced insights across multiple critical dimensions:

- **Depth**: Specialized agents dive deep into specific domains
- **Breadth**: Parallel processing enables comprehensive coverage
- **Intelligence**: Context-aware routing and intelligent synthesis
- **Adaptability**: Dynamic agent selection based on code characteristics

## Tool Arguments and Configuration

### Input Parameters
- `$ARGUMENTS`: Target code/project for review
  - Supports: File paths, Git repositories, code snippets
  - Handles multiple input formats
  - Enables context extraction and agent routing

### Agent Types
1. Code Quality Reviewers
2. Security Auditors
3. Architecture Specialists
4. Performance Analysts
5. Compliance Validators
6. Best Practices Experts

## Multi-Agent Coordination Strategy

### 1. Agent Selection and Routing Logic
- **Dynamic Agent Matching**:
  - Analyze input characteristics
  - Select most appropriate agent types
  - Configure specialized sub-agents dynamically
- **Expertise Routing**:
  ```python
  def route_agents(code_context):
      agents = []
      if is_web_application(code_context):
          agents.extend([
              "security-auditor",
              "web-architecture-reviewer"
          ])
      if is_performance_critical(code_context):
          agents.append("performance-analyst")
      return agents
  ```

### 2. Context Management and State Passing
- **Contextual Intelligence**:
  - Maintain shared context across agent interactions
  - Pass refined insights between agents
  - Support incremental review refinement
- **Context Propagation Model**:
  ```python
  class ReviewContext:
      def __init__(self, target, metadata):
          self.target = target
          self.metadata = metadata
          self.agent_insights = {}

      def update_insights(self, agent_type, insights):
          self.agent_insights[agent_type] = insights
  ```

### 3. Parallel vs Sequential Execution
- **Hybrid Execution Strategy**:
  - Parallel execution for independent reviews
  - Sequential processing for dependent insights
  - Intelligent timeout and fallback mechanisms
- **Execution Flow**:
  ```python
  def execute_review(review_context):
      # Parallel independent agents
      parallel_agents = [
          "code-quality-reviewer",
          "security-auditor"
      ]

      # Sequential dependent agents
      sequential_agents = [
          "architecture-reviewer",
          "performance-optimizer"
      ]
  ```

### 4. Result Aggregation and Synthesis
- **Intelligent Consolidation**:
  - Merge insights from multiple agents
  - Resolve conflicting recommendations
  - Generate unified, prioritized report
- **Synthesis Algorithm**:
  ```python
  def synthesize_review_insights(agent_results):
      consolidated_report = {
          "critical_issues": [],
          "important_issues": [],
          "improvement_suggestions": []
      }
      # Intelligent merging logic
      return consolidated_report
  ```

### 5. Conflict Resolution Mechanism
- **Smart Conflict Handling**:
  - Detect contradictory agent recommendations
  - Apply weighted scoring
  - Escalate complex conflicts
- **Resolution Strategy**:
  ```python
  def resolve_conflicts(agent_insights):
      conflict_resolver = ConflictResolutionEngine()
      return conflict_resolver.process(agent_insights)
  ```

### 6. Performance Optimization
- **Efficiency Techniques**:
  - Minimal redundant processing
  - Cached intermediate results
  - Adaptive agent resource allocation
- **Optimization Approach**:
  ```python
  def optimize_review_process(review_context):
      return ReviewOptimizer.allocate_resources(review_context)
  ```

### 7. Quality Validation Framework
- **Comprehensive Validation**:
  - Cross-agent result verification
  - Statistical confi
