---
name: evaluation
description: Build evaluation frameworks for agent systems. Use when testing agent performance systematically, validating context engineering choices, or measuring improvements over time. 
category: AI & Agents
source: antigravity
tags: [python, api, ai, agent, llm, automation, design, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/evaluation
---


## When to Use This Skill

Build evaluation frameworks for agent systems

Use this skill when working with build evaluation frameworks for agent systems.
# Evaluation Methods for Agent Systems

Evaluation of agent systems requires different approaches than traditional software or even standard language model applications. Agents make dynamic decisions, are non-deterministic between runs, and often lack single correct answers. Effective evaluation must account for these characteristics while providing actionable feedback. A robust evaluation framework enables continuous improvement, catches regressions, and validates that context engineering choices achieve intended effects.

## When to Use
Activate this skill when:
- Testing agent performance systematically
- Validating context engineering choices
- Measuring improvements over time
- Catching regressions before deployment
- Building quality gates for agent pipelines
- Comparing different agent configurations
- Evaluating production systems continuously

## Core Concepts

Agent evaluation requires outcome-focused approaches that account for non-determinism and multiple valid paths. Multi-dimensional rubrics capture various quality aspects: factual accuracy, completeness, citation accuracy, source quality, and tool efficiency. LLM-as-judge provides scalable evaluation while human evaluation catches edge cases.

The key insight is that agents may find alternative paths to goals—the evaluation should judge whether they achieve right outcomes while following reasonable processes.

**Performance Drivers: The 95% Finding**
[Anthropic's June 2025 engineering report](https://www.anthropic.com/engineering/multi-agent-research-system) described an analysis of BrowseComp in which three factors explained 95% of variance. This is a reported association in that setting, not a causal guarantee or a universal evaluation rule:

| Factor | Variance Explained | Implication |
|--------|-------------------|-------------|
| Token usage | 80% | More tokens = better performance |
| Tool calls and model choice | Joint factors in the reported analysis; separate percentages not supplied | Compare under matched budgets |

This finding has significant implications for evaluation design:
- **Token budgets matter**: Evaluate agents with realistic token budgets, not unlimited resources
- **Model upgrades beat token increases**: The report compared Sonnet 4 with Sonnet 3.7; measure current models on your task rather than extrapolating that comparison
- **Multi-agent validation**: The finding validates architectures that distribute work across agents with separate context windows

## Detailed Topics

### Evaluation Challenges

**Non-Determinism and Multiple Valid Paths**
Agents may take completely different valid paths to reach goals. One agent might search three sources while another searches ten. They might use different tools to find the same answer. Traditional evaluations that check for specific steps fail in this context.

The solution is outcome-focused evaluation that judges whether agents achieve right outcomes while following reasonable processes.

**Context-Dependent Failures**
Agent failures often depend on context in subtle ways. An agent might succeed on simple queries but fail on complex ones. It might work well with one tool set but fail with another. Failures may emerge only after extended interaction when context accumulates.

Evaluation must cover a range of complexity levels and test extended interactions, not just isolated queries.

**Composite Quality Dimensions**
Agent quality is not a single dimension. It includes factual accuracy, completeness, coherence, tool efficiency, and process quality. An agent might score high on accuracy but low in efficiency, or vice versa.

Evaluation rubrics must capture multiple dimensions with appropriate weighting for the use case.

### Evaluation Rubric Design

**Multi-Dimensional Rubric**
Effective rubrics cover key dimensions with descriptive levels:

Factual accuracy: Claims match ground truth (excellent to failed)

Completeness: Output covers requested aspects (excellent to failed)

Citation accuracy: Citations match claimed sources (excellent to failed)

Source quality: Uses appropriate primary sources (excellent to failed)

Tool efficiency: Uses right tools reasonable number of times (excellent to failed)

**Rubric Scoring**
Convert dimension assessments to numeric scores (0.0 to 1.0) with appropriate weighting. Calculate weighted overall scores. Determine passing threshold based on use case requirements.

### Evaluation Methodologies

**LLM-as-Judge**
LLM-based evaluation scales to large test sets and provides consistent judgments. The key is designing effective evaluation prompts that capture the dimensions of interest.

Provide clear task description, agent output, ground truth (if available), evaluation scale with level descriptions, and request structured judgment.

**Human Evaluation**
Human evaluation catches what automa
