---
name: agent-orchestration-improve-agent
description: Systematic improvement of existing agents through performance analysis, prompt engineering, and continuous iteration. 
category: AI & Agents
source: antigravity
tags: [markdown, api, ai, agent, workflow, template, design, document, presentation, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-orchestration-improve-agent
---


# Agent Performance Optimization Workflow

Systematic improvement of existing agents through performance analysis, prompt engineering, and continuous iteration.

[Extended thinking: Agent optimization requires a data-driven approach combining performance metrics, user feedback analysis, and advanced prompt engineering techniques. Success depends on systematic evaluation, targeted improvements, and rigorous testing with rollback capabilities for production safety.]

## Use this skill when

- Improving an existing agent's performance or reliability
- Analyzing failure modes, prompt quality, or tool usage
- Running structured A/B tests or evaluation suites
- Designing iterative optimization workflows for agents

## Do not use this skill when

- You are building a brand-new agent from scratch
- There are no metrics, feedback, or test cases available
- The task is unrelated to agent performance or prompt quality

## Instructions

1. Establish baseline metrics and collect representative examples.
2. Identify failure modes and prioritize high-impact fixes.
3. Apply prompt and workflow improvements with measurable goals.
4. Validate with tests and roll out changes in controlled stages.

## Safety

- Avoid deploying prompt changes without regression testing.
- Roll back quickly if quality or safety metrics regress.

## Phase 1: Performance Analysis and Baseline Metrics

Comprehensive analysis of agent performance using context-manager for historical data collection.

### 1.1 Gather Performance Data

```
Use: context-manager
Command: analyze-agent-performance $ARGUMENTS --days 30
```

Collect metrics including:

- Task completion rate (successful vs failed tasks)
- Response accuracy and factual correctness
- Tool usage efficiency (correct tools, call frequency)
- Average response time and token consumption
- User satisfaction indicators (corrections, retries)
- Hallucination incidents and error patterns

### 1.2 User Feedback Pattern Analysis

Identify recurring patterns in user interactions:

- **Correction patterns**: Where users consistently modify outputs
- **Clarification requests**: Common areas of ambiguity
- **Task abandonment**: Points where users give up
- **Follow-up questions**: Indicators of incomplete responses
- **Positive feedback**: Successful patterns to preserve

### 1.3 Failure Mode Classification

Categorize failures by root cause:

- **Instruction misunderstanding**: Role or task confusion
- **Output format errors**: Structure or formatting issues
- **Context loss**: Long conversation degradation
- **Tool misuse**: Incorrect or inefficient tool selection
- **Constraint violations**: Safety or business rule breaches
- **Edge case handling**: Unusual input scenarios

### 1.4 Baseline Performance Report

Generate quantitative baseline metrics:

```
Performance Baseline:
- Task Success Rate: [X%]
- Average Corrections per Task: [Y]
- Tool Call Efficiency: [Z%]
- User Satisfaction Score: [1-10]
- Average Response Latency: [Xms]
- Token Efficiency Ratio: [X:Y]
```

## Phase 2: Prompt Engineering Improvements

Apply advanced prompt optimization techniques using prompt-engineer agent.

### 2.1 Chain-of-Thought Enhancement

Implement structured reasoning patterns:

```
Use: prompt-engineer
Technique: chain-of-thought-optimization
```

- Add explicit reasoning steps: "Let's approach this step-by-step..."
- Include self-verification checkpoints: "Before proceeding, verify that..."
- Implement recursive decomposition for complex tasks
- Add reasoning trace visibility for debugging

### 2.2 Few-Shot Example Optimization

Curate high-quality examples from successful interactions:

- **Select diverse examples** covering common use cases
- **Include edge cases** that previously failed
- **Show both positive and negative examples** with explanations
- **Order examples** from simple to complex
- **Annotate examples** with key decision points

Example structure:

```
Good Example:
Input: [User request]
Reasoning: [Step-by-step thought process]
Output: [Successful response]
Why this works: [Key success factors]

Bad Example:
Input: [Similar request]
Output: [Failed response]
Why this fails: [Specific issues]
Correct approach: [Fixed version]
```

### 2.3 Role Definition Refinement

Strengthen agent identity and capabilities:

- **Core purpose**: Clear, single-sentence mission
- **Expertise domains**: Specific knowledge areas
- **Behavioral traits**: Personality and interaction style
- **Tool proficiency**: Available tools and when to use them
- **Constraints**: What the agent should NOT do
- **Success criteria**: How to measure task completion

### 2.4 Constitutional AI Integration

Implement self-correction mechanisms:

```
Constitutional Principles:
1. Verify factual accuracy before responding
2. Self-check for potential biases or harmful content
3. Validate output format matches requirements
4. Ensure response completeness
5. Maintain consistency with previous responses
```

Add critique-and-revise loops:

- In
