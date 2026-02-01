---
name: tool-design
description: Build tools that agents can use effectively, including architectural reduction patterns 
category: AI & Agents
source: antigravity
tags: [python, api, mcp, claude, ai, agent, workflow, design, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/tool-design
---


## When to Use This Skill

Build tools that agents can use effectively, including architectural reduction patterns

Use this skill when working with build tools that agents can use effectively, including architectural reduction patterns.
# Tool Design for Agents

Tools are the primary mechanism through which agents interact with the world. They define the contract between deterministic systems and non-deterministic agents. Unlike traditional software APIs designed for developers, tool APIs must be designed for language models that reason about intent, infer parameter values, and generate calls from natural language requests. Poor tool design creates failure modes that no amount of prompt engineering can fix. Effective tool design follows specific principles that account for how agents perceive and use tools.

## When to Activate

Activate this skill when:
- Creating new tools for agent systems
- Debugging tool-related failures or misuse
- Optimizing existing tool sets for better agent performance
- Designing tool APIs from scratch
- Evaluating third-party tools for agent integration
- Standardizing tool conventions across a codebase

## Core Concepts

Tools are contracts between deterministic systems and non-deterministic agents. The consolidation principle states that if a human engineer cannot definitively say which tool should be used in a given situation, an agent cannot be expected to do better. Effective tool descriptions are prompt engineering that shapes agent behavior.

Key principles include: clear descriptions that answer what, when, and what returns; response formats that balance completeness and token efficiency; error messages that enable recovery; and consistent conventions that reduce cognitive load.

## Detailed Topics

### The Tool-Agent Interface

**Tools as Contracts**
Tools are contracts between deterministic systems and non-deterministic agents. When humans call APIs, they understand the contract and make appropriate requests. Agents must infer the contract from descriptions and generate calls that match expected formats.

This fundamental difference requires rethinking API design. The contract must be unambiguous, examples must illustrate expected patterns, and error messages must guide correction. Every ambiguity in tool definitions becomes a potential failure mode.

**Tool Description as Prompt**
Tool descriptions are loaded into agent context and collectively steer behavior. The descriptions are not just documentation—they are prompt engineering that shapes how agents reason about tool use.

Poor descriptions like "Search the database" with cryptic parameter names force agents to guess. Optimized descriptions include usage context, examples, and defaults. The description answers: what the tool does, when to use it, and what it produces.

**Namespacing and Organization**
As tool collections grow, organization becomes critical. Namespacing groups related tools under common prefixes, helping agents select appropriate tools at the right time.

Namespacing creates clear boundaries between functionality. When an agent needs database information, it routes to the database namespace. When it needs web search, it routes to web namespace.

### The Consolidation Principle

**Single Comprehensive Tools**
The consolidation principle states that if a human engineer cannot definitively say which tool should be used in a given situation, an agent cannot be expected to do better. This leads to a preference for single comprehensive tools over multiple narrow tools.

Instead of implementing list_users, list_events, and create_event, implement schedule_event that finds availability and schedules. The comprehensive tool handles the full workflow internally rather than requiring agents to chain multiple calls.

**Why Consolidation Works**
Agents have limited context and attention. Each tool in the collection competes for attention in the tool selection phase. Each tool adds description tokens that consume context budget. Overlapping functionality creates ambiguity about which tool to use.

Consolidation reduces token consumption by eliminating redundant descriptions. It eliminates ambiguity by having one tool cover each workflow. It reduces tool selection complexity by shrinking the effective tool set.

**When Not to Consolidate**
Consolidation is not universally correct. Tools with fundamentally different behaviors should remain separate. Tools used in different contexts benefit from separation. Tools that might be called independently should not be artificially bundled.

### Architectural Reduction

The consolidation principle, taken to its logical extreme, leads to architectural reduction: removing most specialized tools in favor of primitive, general-purpose capabilities. Production evidence shows this approach can outperform sophisticated multi-tool architectures.

**The File System Agent Pattern**
Instead of building custom tools for data exploration, schema lookup, and query validation, provide 
