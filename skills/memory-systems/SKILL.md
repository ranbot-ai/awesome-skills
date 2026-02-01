---
name: memory-systems
description: Design short-term, long-term, and graph-based memory architectures 
category: AI & Agents
source: antigravity
tags: [python, ai, agent, gpt, design, document, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/memory-systems
---


## When to Use This Skill

Design short-term, long-term, and graph-based memory architectures

Use this skill when working with design short-term, long-term, and graph-based memory architectures.
# Memory System Design

Memory provides the persistence layer that allows agents to maintain continuity across sessions and reason over accumulated knowledge. Simple agents rely entirely on context for memory, losing all state when sessions end. Sophisticated agents implement layered memory architectures that balance immediate context needs with long-term knowledge retention. The evolution from vector stores to knowledge graphs to temporal knowledge graphs represents increasing investment in structured memory for improved retrieval and reasoning.

## When to Activate

Activate this skill when:
- Building agents that must persist across sessions
- Needing to maintain entity consistency across conversations
- Implementing reasoning over accumulated knowledge
- Designing systems that learn from past interactions
- Creating knowledge bases that grow over time
- Building temporal-aware systems that track state changes

## Core Concepts

Memory exists on a spectrum from immediate context to permanent storage. At one extreme, working memory in the context window provides zero-latency access but vanishes when sessions end. At the other extreme, permanent storage persists indefinitely but requires retrieval to enter context.

Simple vector stores lack relationship and temporal structure. Knowledge graphs preserve relationships for reasoning. Temporal knowledge graphs add validity periods for time-aware queries. Implementation choices depend on query complexity, infrastructure constraints, and accuracy requirements.

## Detailed Topics

### Memory Architecture Fundamentals

**The Context-Memory Spectrum**
Memory exists on a spectrum from immediate context to permanent storage. At one extreme, working memory in the context window provides zero-latency access but vanishes when sessions end. At the other extreme, permanent storage persists indefinitely but requires retrieval to enter context. Effective architectures use multiple layers along this spectrum.

The spectrum includes working memory (context window, zero latency, volatile), short-term memory (session-persistent, searchable, volatile), long-term memory (cross-session persistent, structured, semi-permanent), and permanent memory (archival, queryable, permanent). Each layer has different latency, capacity, and persistence characteristics.

**Why Simple Vector Stores Fall Short**
Vector RAG provides semantic retrieval by embedding queries and documents in a shared embedding space. Similarity search retrieves the most semantically similar documents. This works well for document retrieval but lacks structure for agent memory.

Vector stores lose relationship information. If an agent learns that "Customer X purchased Product Y on Date Z," a vector store can retrieve this fact if asked directly. But it cannot answer "What products did customers who purchased Product Y also buy?" because relationship structure is not preserved.

Vector stores also struggle with temporal validity. Facts change over time, but vector stores provide no mechanism to distinguish "current fact" from "outdated fact" except through explicit metadata and filtering.

**The Move to Graph-Based Memory**
Knowledge graphs preserve relationships between entities. Instead of isolated document chunks, graphs encode that Entity A has Relationship R to Entity B. This enables queries that traverse relationships rather than just similarity.

Temporal knowledge graphs add validity periods to facts. Each fact has a "valid from" and optionally "valid until" timestamp. This enables time-travel queries that reconstruct knowledge at specific points in time.

**Benchmark Performance Comparison**
The Deep Memory Retrieval (DMR) benchmark provides concrete performance data across memory architectures:

| Memory System | DMR Accuracy | Retrieval Latency | Notes |
|---------------|--------------|-------------------|-------|
| Zep (Temporal KG) | 94.8% | 2.58s | Best accuracy, fast retrieval |
| MemGPT | 93.4% | Variable | Good general performance |
| GraphRAG | ~75-85% | Variable | 20-35% gains over baseline RAG |
| Vector RAG | ~60-70% | Fast | Loses relationship structure |
| Recursive Summarization | 35.3% | Low | Severe information loss |

Zep demonstrated 90% reduction in retrieval latency compared to full-context baselines (2.58s vs 28.9s for GPT-5.2). This efficiency comes from retrieving only relevant subgraphs rather than entire context history.

GraphRAG achieves approximately 20-35% accuracy gains over baseline RAG in complex reasoning tasks and reduces hallucination by up to 30% through community-based summarization.

### Memory Layer Architecture

**Layer 1: Working Memory**
Working memory is the context window itself. It provides immediate access to information currently being processed but has limited capacit
