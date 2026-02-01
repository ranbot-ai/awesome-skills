---
name: context-optimization
description: Apply compaction, masking, and caching strategies 
category: AI & Agents
source: antigravity
tags: [python, ai, agent, template, design, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/context-optimization
---


## When to Use This Skill

Apply compaction, masking, and caching strategies

Use this skill when working with apply compaction, masking, and caching strategies.
# Context Optimization Techniques

Context optimization extends the effective capacity of limited context windows through strategic compression, masking, caching, and partitioning. The goal is not to magically increase context windows but to make better use of available capacity. Effective optimization can double or triple effective context capacity without requiring larger models or longer contexts.

## When to Activate

Activate this skill when:
- Context limits constrain task complexity
- Optimizing for cost reduction (fewer tokens = lower costs)
- Reducing latency for long conversations
- Implementing long-running agent systems
- Needing to handle larger documents or conversations
- Building production systems at scale

## Core Concepts

Context optimization extends effective capacity through four primary strategies: compaction (summarizing context near limits), observation masking (replacing verbose outputs with references), KV-cache optimization (reusing cached computations), and context partitioning (splitting work across isolated contexts).

The key insight is that context quality matters more than quantity. Optimization preserves signal while reducing noise. The art lies in selecting what to keep versus what to discard, and when to apply each technique.

## Detailed Topics

### Compaction Strategies

**What is Compaction**
Compaction is the practice of summarizing context contents when approaching limits, then reinitializing a new context window with the summary. This distills the contents of a context window in a high-fidelity manner, enabling the agent to continue with minimal performance degradation.

Compaction typically serves as the first lever in context optimization. The art lies in selecting what to keep versus what to discard.

**Compaction Implementation**
Compaction works by identifying sections that can be compressed, generating summaries that capture essential points, and replacing full content with summaries. Priority for compression goes to tool outputs (replace with summaries), old turns (summarize early conversation), retrieved docs (summarize if recent versions exist), and never compress system prompt.

**Summary Generation**
Effective summaries preserve different elements depending on message type:

Tool outputs: Preserve key findings, metrics, and conclusions. Remove verbose raw output.

Conversational turns: Preserve key decisions, commitments, and context shifts. Remove filler and back-and-forth.

Retrieved documents: Preserve key facts and claims. Remove supporting evidence and elaboration.

### Observation Masking

**The Observation Problem**
Tool outputs can comprise 80%+ of token usage in agent trajectories. Much of this is verbose output that has already served its purpose. Once an agent has used a tool output to make a decision, keeping the full output provides diminishing value while consuming significant context.

Observation masking replaces verbose tool outputs with compact references. The information remains accessible if needed but does not consume context continuously.

**Masking Strategy Selection**
Not all observations should be masked equally:

Never mask: Observations critical to current task, observations from the most recent turn, observations used in active reasoning.

Consider masking: Observations from 3+ turns ago, verbose outputs with key points extractable, observations whose purpose has been served.

Always mask: Repeated outputs, boilerplate headers/footers, outputs already summarized in conversation.

### KV-Cache Optimization

**Understanding KV-Cache**
The KV-cache stores Key and Value tensors computed during inference, growing linearly with sequence length. Caching the KV-cache across requests sharing identical prefixes avoids recomputation.

Prefix caching reuses KV blocks across requests with identical prefixes using hash-based block matching. This dramatically reduces cost and latency for requests with common prefixes like system prompts.

**Cache Optimization Patterns**
Optimize for caching by reordering context elements to maximize cache hits. Place stable elements first (system prompt, tool definitions), then frequently reused elements, then unique elements last.

Design prompts to maximize cache stability: avoid dynamic content like timestamps, use consistent formatting, keep structure stable across sessions.

### Context Partitioning

**Sub-Agent Partitioning**
The most aggressive form of context optimization is partitioning work across sub-agents with isolated contexts. Each sub-agent operates in a clean context focused on its subtask without carrying accumulated context from other subtasks.

This approach achieves separation of concerns—the detailed search context remains isolated within sub-agents while the coordinator focuses on synthesis and analysis.

**Result Aggregation
