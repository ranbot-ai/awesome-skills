---
name: agent-memory-systems
description: Memory is the cornerstone of intelligent agents. Without it, every interaction starts from zero. This skill covers the architecture of agent memory: short-term (context window), long-term (vector stor
category: AI & Agents
source: antigravity
tags: [python, markdown, api, ai, agent, llm, gpt, workflow, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-memory-systems
---


# Agent Memory Systems

Memory is the cornerstone of intelligent agents. Without it, every interaction
starts from zero. This skill covers the architecture of agent memory: short-term
(context window), long-term (vector stores), and the cognitive architectures
that organize them.

Key insight: Memory isn't just storage - it's retrieval. A million stored facts
mean nothing if you can't find the right one. Chunking, embedding, and retrieval
strategies determine whether your agent remembers or forgets.

The field is fragmented with inconsistent terminology. We use the CoALA cognitive
architecture framework: semantic memory (facts), episodic memory (experiences),
and procedural memory (how-to knowledge).

## Principles

- Memory quality = retrieval quality, not storage quantity
- Chunk for retrieval, not for storage
- Context isolation is the enemy of memory
- Right memory type for right information
- Decay old memories - not everything should be forever
- Test retrieval accuracy before production
- Background memory formation beats real-time

## Capabilities

- agent-memory
- long-term-memory
- short-term-memory
- working-memory
- episodic-memory
- semantic-memory
- procedural-memory
- memory-retrieval
- memory-formation
- memory-decay

## Scope

- vector-database-operations → data-engineer
- rag-pipeline-architecture → llm-architect
- embedding-model-selection → ml-engineer
- knowledge-graph-design → knowledge-engineer

## Tooling

### Memory_frameworks

- LangMem (LangChain) - When: LangGraph agents with persistent memory Note: Semantic, episodic, procedural memory types
- MemGPT / Letta - When: Virtual context management, OS-style memory Note: Hierarchical memory tiers, automatic paging
- Mem0 - When: User memory layer for personalization Note: Designed for user preferences and history

### Vector_stores

- Pinecone - When: Managed, enterprise-scale (billions of vectors) Note: Best query performance, highest cost
- Qdrant - When: Complex metadata filtering, open-source Note: Rust-based, excellent filtering
- Weaviate - When: Hybrid search, knowledge graph features Note: GraphQL interface, good for relationships
- ChromaDB - When: Prototyping, small/medium apps Note: Developer-friendly, ~20ms p50 at 100K vectors
- pgvector - When: Already using PostgreSQL, simpler setup Note: Good for <1M vectors, familiar tooling

### Embedding_models

- OpenAI text-embedding-3-large - When: Best quality, 3072 dimensions Note: $0.13/1M tokens
- OpenAI text-embedding-3-small - When: Good balance, 1536 dimensions Note: $0.02/1M tokens, 5x cheaper
- nomic-embed-text-v1.5 - When: Open-source, local deployment Note: 768 dimensions, good quality
- all-MiniLM-L6-v2 - When: Lightweight, fast local embedding Note: 384 dimensions, lowest latency

## Patterns

### Memory Type Architecture

Choosing the right memory type for different information

**When to use**: Designing agent memory system

# MEMORY TYPE ARCHITECTURE (CoALA Framework):

"""
Three memory types for different purposes:

1. Semantic Memory: Facts and knowledge
   - What you know about the world
   - User preferences, domain knowledge
   - Stored in profiles (structured) or collections (unstructured)

2. Episodic Memory: Experiences and events
   - What happened (timestamped events)
   - Past conversations, task outcomes
   - Used for learning from experience

3. Procedural Memory: How to do things
   - Rules, skills, workflows
   - Often implemented as few-shot examples
   - "How did I solve this before?"
"""

## LangMem Implementation
"""
from langmem import MemoryStore
from langgraph.graph import StateGraph

# Initialize memory store
memory = MemoryStore(
    connection_string=os.environ["POSTGRES_URL"]
)

# Semantic memory: user profile
await memory.semantic.upsert(
    namespace="user_profile",
    key=user_id,
    content={
        "name": "Alice",
        "preferences": ["dark mode", "concise responses"],
        "expertise_level": "developer",
    }
)

# Episodic memory: past interaction
await memory.episodic.add(
    namespace="conversations",
    content={
        "timestamp": datetime.now(),
        "summary": "Helped debug authentication issue",
        "outcome": "resolved",
        "key_insights": ["Token expiry was root cause"],
    },
    metadata={"user_id": user_id, "topic": "debugging"}
)

# Procedural memory: learned pattern
await memory.procedural.add(
    namespace="skills",
    content={
        "task_type": "debug_auth",
        "steps": ["Check token expiry", "Verify refresh flow"],
        "example_interaction": few_shot_example,
    }
)
"""

## Memory Retrieval at Runtime
"""
async def prepare_context(user_id, query):
    # Get user profile (semantic)
    profile = await memory.semantic.get(
        namespace="user_profile",
        key=user_id
    )

    # Find relevant past experiences (episodic)
    similar_experiences = await memory.episodic.search(
        namespace="conversations",
        query=query,
        filter={"user_id": user_id
