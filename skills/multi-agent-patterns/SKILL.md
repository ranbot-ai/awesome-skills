---
name: multi-agent-patterns
description: Master orchestrator, peer-to-peer, and hierarchical multi-agent architectures 
category: AI & Agents
source: antigravity
tags: [python, node, claude, ai, agent, gpt, workflow, design, document, langgraph]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/multi-agent-patterns
---


## When to Use This Skill

Master orchestrator, peer-to-peer, and hierarchical multi-agent architectures

Use this skill when working with master orchestrator, peer-to-peer, and hierarchical multi-agent architectures.
# Multi-Agent Architecture Patterns

Multi-agent architectures distribute work across multiple language model instances, each with its own context window. When designed well, this distribution enables capabilities beyond single-agent limits. When designed poorly, it introduces coordination overhead that negates benefits. The critical insight is that sub-agents exist primarily to isolate context, not to anthropomorphize role division.

## When to Activate

Activate this skill when:
- Single-agent context limits constrain task complexity
- Tasks decompose naturally into parallel subtasks
- Different subtasks require different tool sets or system prompts
- Building systems that must handle multiple domains simultaneously
- Scaling agent capabilities beyond single-context limits
- Designing production agent systems with multiple specialized components

## Core Concepts

Multi-agent systems address single-agent context limitations through distribution. Three dominant patterns exist: supervisor/orchestrator for centralized control, peer-to-peer/swarm for flexible handoffs, and hierarchical for layered abstraction. The critical design principle is context isolation—sub-agents exist primarily to partition context rather than to simulate organizational roles.

Effective multi-agent systems require explicit coordination protocols, consensus mechanisms that avoid sycophancy, and careful attention to failure modes including bottlenecks, divergence, and error propagation.

## Detailed Topics

### Why Multi-Agent Architectures

**The Context Bottleneck**
Single agents face inherent ceilings in reasoning capability, context management, and tool coordination. As tasks grow more complex, context windows fill with accumulated history, retrieved documents, and tool outputs. Performance degrades according to predictable patterns: the lost-in-middle effect, attention scarcity, and context poisoning.

Multi-agent architectures address these limitations by partitioning work across multiple context windows. Each agent operates in a clean context focused on its subtask. Results aggregate at a coordination layer without any single context bearing the full burden.

**The Token Economics Reality**
Multi-agent systems consume significantly more tokens than single-agent approaches. Production data shows:

| Architecture | Token Multiplier | Use Case |
|--------------|------------------|----------|
| Single agent chat | 1× baseline | Simple queries |
| Single agent with tools | ~4× baseline | Tool-using tasks |
| Multi-agent system | ~15× baseline | Complex research/coordination |

Research on the BrowseComp evaluation found that three factors explain 95% of performance variance: token usage (80% of variance), number of tool calls, and model choice. This validates the multi-agent approach of distributing work across agents with separate context windows to add capacity for parallel reasoning.

Critically, upgrading to better models often provides larger performance gains than doubling token budgets. Claude Sonnet 4.5 showed larger gains than doubling tokens on earlier Sonnet versions. GPT-5.2's thinking mode similarly outperforms raw token increases. This suggests model selection and multi-agent architecture are complementary strategies.

**The Parallelization Argument**
Many tasks contain parallelizable subtasks that a single agent must execute sequentially. A research task might require searching multiple independent sources, analyzing different documents, or comparing competing approaches. A single agent processes these sequentially, accumulating context with each step.

Multi-agent architectures assign each subtask to a dedicated agent with a fresh context. All agents work simultaneously, then return results to a coordinator. The total real-world time approaches the duration of the longest subtask rather than the sum of all subtasks.

**The Specialization Argument**
Different tasks benefit from different agent configurations: different system prompts, different tool sets, different context structures. A general-purpose agent must carry all possible configurations in context. Specialized agents carry only what they need.

Multi-agent architectures enable specialization without combinatorial explosion. The coordinator routes to specialized agents; each agent operates with lean context optimized for its domain.

### Architectural Patterns

**Pattern 1: Supervisor/Orchestrator**
The supervisor pattern places a central agent in control, delegating to specialists and synthesizing results. The supervisor maintains global state and trajectory, decomposes user objectives into subtasks, and routes to appropriate workers.

```
User Query -> Supervisor -> [Specialist, Specialist, Specialist] -> Aggregation -> Final Output
```

When
