---
name: conversation-memory
description: Persistent memory systems for LLM conversations including short-term, long-term, and entity-based memory 
category: Security & Systems
source: antigravity
tags: [ai, llm, workflow, design, vulnerability, langchain, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/conversation-memory
---


# Conversation Memory

Persistent memory systems for LLM conversations including short-term, long-term, and entity-based memory

## Capabilities

- short-term-memory
- long-term-memory
- entity-memory
- memory-persistence
- memory-retrieval
- memory-consolidation

## Prerequisites

- Knowledge: LLM conversation patterns, Database basics, Key-value stores
- Skills_recommended: context-window-management, rag-implementation

## Scope

- Does_not_cover: Knowledge graph construction, Semantic search implementation, Database administration
- Boundaries: Focus is memory patterns for LLMs, Covers storage and retrieval strategies

## Ecosystem

### Primary_tools

- Mem0 - Memory layer for AI applications
- LangChain Memory - Memory utilities in LangChain
- Redis - In-memory data store for session memory

## Patterns

### Tiered Memory System

Different memory tiers for different purposes

**When to use**: Building any conversational AI

interface MemorySystem {
    // Buffer: Current conversation (in context)
    buffer: ConversationBuffer;

    // Short-term: Recent interactions (session)
    shortTerm: ShortTermMemory;

    // Long-term: Persistent across sessions
    longTerm: LongTermMemory;

    // Entity: Facts about people, places, things
    entity: EntityMemory;
}

class TieredMemory implements MemorySystem {
    async addMessage(message: Message): Promise<void> {
        // Always add to buffer
        this.buffer.add(message);

        // Extract entities
        const entities = await extractEntities(message);
        for (const entity of entities) {
            await this.entity.upsert(entity);
        }

        // Check for memorable content
        if (await isMemoryWorthy(message)) {
            await this.shortTerm.add({
                content: message.content,
                timestamp: Date.now(),
                importance: await scoreImportance(message)
            });
        }
    }

    async consolidate(): Promise<void> {
        // Move important short-term to long-term
        const memories = await this.shortTerm.getOld(24 * 60 * 60 * 1000);
        for (const memory of memories) {
            if (memory.importance > 0.7 || memory.referenced > 2) {
                await this.longTerm.add(memory);
            }
            await this.shortTerm.remove(memory.id);
        }
    }

    async buildContext(query: string): Promise<string> {
        const parts: string[] = [];

        // Relevant long-term memories
        const longTermRelevant = await this.longTerm.search(query, 3);
        if (longTermRelevant.length) {
            parts.push('## Relevant Memories\n' +
                longTermRelevant.map(m => `- ${m.content}`).join('\n'));
        }

        // Relevant entities
        const entities = await this.entity.getRelevant(query);
        if (entities.length) {
            parts.push('## Known Entities\n' +
                entities.map(e => `- ${e.name}: ${e.facts.join(', ')}`).join('\n'));
        }

        // Recent conversation
        const recent = this.buffer.getRecent(10);
        parts.push('## Recent Conversation\n' + formatMessages(recent));

        return parts.join('\n\n');
    }
}

### Entity Memory

Store and update facts about entities

**When to use**: Need to remember details about people, places, things

interface Entity {
    id: string;
    name: string;
    type: 'person' | 'place' | 'thing' | 'concept';
    facts: Fact[];
    lastMentioned: number;
    mentionCount: number;
}

interface Fact {
    content: string;
    confidence: number;
    source: string;  // Which message this came from
    timestamp: number;
}

class EntityMemory {
    async extractAndStore(message: Message): Promise<void> {
        // Use LLM to extract entities and facts
        const extraction = await llm.complete(`
            Extract entities and facts from this message.
            Return JSON: { "entities": [
                { "name": "...", "type": "...", "facts": ["..."] }
            ]}

            Message: "${message.content}"
        `);

        const { entities } = JSON.parse(extraction);
        for (const entity of entities) {
            await this.upsert(entity, message.id);
        }
    }

    async upsert(entity: ExtractedEntity, sourceId: string): Promise<void> {
        const existing = await this.store.get(entity.name.toLowerCase());

        if (existing) {
            // Merge facts, avoiding duplicates
            for (const fact of entity.facts) {
                if (!this.hasSimilarFact(existing.facts, fact)) {
                    existing.facts.push({
                        content: fact,
                        confidence: 0.9,
                        source: sourceId,
                        timestamp: Date.now()
                    });
                }
            }
            existing.lastMentioned = Date.now();
            existing.mentionCount++;
            await this.store.set(existing.id, existing);
        } else {
            // Create new
