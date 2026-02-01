---
name: git-pr-workflows-git-workflow
description: Orchestrate a comprehensive git workflow from code review through PR creation, leveraging specialized agents for quality assurance, testing, and deployment readiness. This workflow implements modern g
category: AI & Agents
source: antigravity
tags: [markdown, api, ai, agent, llm, automation, workflow, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/git-pr-workflows-git-workflow
---


# Complete Git Workflow with Multi-Agent Orchestration

Orchestrate a comprehensive git workflow from code review through PR creation, leveraging specialized agents for quality assurance, testing, and deployment readiness. This workflow implements modern git best practices including Conventional Commits, automated testing, and structured PR creation.

[Extended thinking: This workflow coordinates multiple specialized agents to ensure code quality before commits are made. The code-reviewer agent performs initial quality checks, test-automator ensures all tests pass, and deployment-engineer verifies production readiness. By orchestrating these agents sequentially with context passing, we prevent broken code from entering the repository while maintaining high velocity. The workflow supports both trunk-based and feature-branch strategies with configurable options for different team needs.]

## Use this skill when

- Working on complete git workflow with multi-agent orchestration tasks or workflows
- Needing guidance, best practices, or checklists for complete git workflow with multi-agent orchestration

## Do not use this skill when

- The task is unrelated to complete git workflow with multi-agent orchestration
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Configuration

**Target branch**: $ARGUMENTS (defaults to 'main' if not specified)

**Supported flags**:
- `--skip-tests`: Skip automated test execution (use with caution)
- `--draft-pr`: Create PR as draft for work-in-progress
- `--no-push`: Perform all checks but don't push to remote
- `--squash`: Squash commits before pushing
- `--conventional`: Enforce Conventional Commits format strictly
- `--trunk-based`: Use trunk-based development workflow
- `--feature-branch`: Use feature branch workflow (default)

## Phase 1: Pre-Commit Review and Analysis

### 1. Code Quality Assessment
- Use Task tool with subagent_type="code-reviewer"
- Prompt: "Review all uncommitted changes for code quality issues. Check for: 1) Code style violations, 2) Security vulnerabilities, 3) Performance concerns, 4) Missing error handling, 5) Incomplete implementations. Generate a detailed report with severity levels (critical/high/medium/low) and provide specific line-by-line feedback. Output format: JSON with {issues: [], summary: {critical: 0, high: 0, medium: 0, low: 0}, recommendations: []}"
- Expected output: Structured code review report for next phase

### 2. Dependency and Breaking Change Analysis
- Use Task tool with subagent_type="code-reviewer"
- Prompt: "Analyze the changes for: 1) New dependencies or version changes, 2) Breaking API changes, 3) Database schema modifications, 4) Configuration changes, 5) Backward compatibility issues. Context from previous review: [insert issues summary]. Identify any changes that require migration scripts or documentation updates."
- Context from previous: Code quality issues that might indicate breaking changes
- Expected output: Breaking change assessment and migration requirements

## Phase 2: Testing and Validation

### 1. Test Execution and Coverage
- Use Task tool with subagent_type="unit-testing::test-automator"
- Prompt: "Execute all test suites for the modified code. Run: 1) Unit tests, 2) Integration tests, 3) End-to-end tests if applicable. Generate coverage report and identify any untested code paths. Based on review issues: [insert critical/high issues], ensure tests cover the problem areas. Provide test results in format: {passed: [], failed: [], skipped: [], coverage: {statements: %, branches: %, functions: %, lines: %}, untested_critical_paths: []}"
- Context from previous: Critical code review issues that need test coverage
- Expected output: Complete test results and coverage metrics

### 2. Test Recommendations and Gap Analysis
- Use Task tool with subagent_type="unit-testing::test-automator"
- Prompt: "Based on test results [insert summary] and code changes, identify: 1) Missing test scenarios, 2) Edge cases not covered, 3) Integration points needing verification, 4) Performance benchmarks needed. Generate test implementation recommendations prioritized by risk. Consider the breaking changes identified: [insert breaking changes]."
- Context from previous: Test results, breaking changes, untested paths
- Expected output: Prioritized list of additional tests needed

## Phase 3: Commit Message Generation

### 1. Change Analysis and Categorization
- Use Task tool with subagent_type="code-reviewer"
- Prompt: "Analyze all changes and categorize them according to Conventional Commits specification. Identify the primary change type (feat/fix/docs/style/refactor/perf/test/build/ci/chore/revert) and scope. For changes: [insert file list and summary], determine if thi
