---
name: prompt-caching
description: Caching strategies for LLM prompts including Anthropic prompt caching, response caching, and CAG (Cache Augmented Generation) 
category: Document Processing
source: antigravity
tags: [api, claude, ai, llm, workflow, document, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/prompt-caching
---


# Prompt Caching

Caching strategies for LLM prompts including Anthropic prompt caching, response caching, and CAG (Cache Augmented Generation)

## Capabilities

- prompt-cache
- response-cache
- kv-cache
- cag-patterns
- cache-invalidation

## Prerequisites

- Knowledge: Caching fundamentals, LLM API usage, Hash functions
- Skills_recommended: context-window-management

## Scope

- Does_not_cover: CDN caching, Database query caching, Static asset caching
- Boundaries: Focus is LLM-specific caching, Covers prompt and response caching

## Ecosystem

### Primary_tools

- Anthropic Prompt Caching - Native prompt caching in Claude API
- Redis - In-memory cache for responses
- OpenAI Caching - Automatic caching in OpenAI API

## Patterns

### Anthropic Prompt Caching

Use Claude's native prompt caching for repeated prefixes

**When to use**: Using Claude API with stable system prompts or context

import Anthropic from '@anthropic-ai/sdk';

const client = new Anthropic();

// Cache the stable parts of your prompt
async function queryWithCaching(userQuery: string) {
    const response = await client.messages.create({
        model: "claude-sonnet-4-20250514",
        max_tokens: 1024,
        system: [
            {
                type: "text",
                text: LONG_SYSTEM_PROMPT,  // Your detailed instructions
                cache_control: { type: "ephemeral" }  // Cache this!
            },
            {
                type: "text",
                text: KNOWLEDGE_BASE,  // Large static context
                cache_control: { type: "ephemeral" }
            }
        ],
        messages: [
            { role: "user", content: userQuery }  // Dynamic part
        ]
    });

    // Check cache usage
    console.log(`Cache read: ${response.usage.cache_read_input_tokens}`);
    console.log(`Cache write: ${response.usage.cache_creation_input_tokens}`);

    return response;
}

// Cost savings: 90% reduction on cached tokens
// Latency savings: Up to 2x faster

### Response Caching

Cache full LLM responses for identical or similar queries

**When to use**: Same queries asked repeatedly

import { createHash } from 'crypto';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

class ResponseCache {
    private ttl = 3600;  // 1 hour default

    // Exact match caching
    async getCached(prompt: string): Promise<string | null> {
        const key = this.hashPrompt(prompt);
        return await redis.get(`response:${key}`);
    }

    async setCached(prompt: string, response: string): Promise<void> {
        const key = this.hashPrompt(prompt);
        await redis.set(`response:${key}`, response, 'EX', this.ttl);
    }

    private hashPrompt(prompt: string): string {
        return createHash('sha256').update(prompt).digest('hex');
    }

    // Semantic similarity caching
    async getSemanticallySimilar(
        prompt: string,
        threshold: number = 0.95
    ): Promise<string | null> {
        const embedding = await embed(prompt);
        const similar = await this.vectorCache.search(embedding, 1);

        if (similar.length && similar[0].similarity > threshold) {
            return await redis.get(`response:${similar[0].id}`);
        }
        return null;
    }

    // Temperature-aware caching
    async getCachedWithParams(
        prompt: string,
        params: { temperature: number; model: string }
    ): Promise<string | null> {
        // Only cache low-temperature responses
        if (params.temperature > 0.5) return null;

        const key = this.hashPrompt(
            `${prompt}|${params.model}|${params.temperature}`
        );
        return await redis.get(`response:${key}`);
    }
}

### Cache Augmented Generation (CAG)

Pre-cache documents in prompt instead of RAG retrieval

**When to use**: Document corpus is stable and fits in context

// CAG: Pre-compute document context, cache in prompt
// Better than RAG when:
// - Documents are stable
// - Total fits in context window
// - Latency is critical

class CAGSystem {
    private cachedContext: string | null = null;
    private lastUpdate: number = 0;

    async buildCachedContext(documents: Document[]): Promise<void> {
        // Pre-process and format documents
        const formatted = documents.map(d =>
            `## ${d.title}\n${d.content}`
        ).join('\n\n');

        // Store with timestamp
        this.cachedContext = formatted;
        this.lastUpdate = Date.now();
    }

    async query(userQuery: string): Promise<string> {
        // Use cached context directly in prompt
        const response = await client.messages.create({
            model: "claude-sonnet-4-20250514",
            max_tokens: 1024,
            system: [
                {
                    type: "text",
                    text: "You are a helpful assistant with access to the following documentation.",
                    cache_control: { type: "ephemeral" }
                },
                {
                    typ
