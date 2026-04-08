---
name: ai-product
description: Every product will be AI-powered. The question is whether you'll build it right or ship a demo that falls apart in production. 
category: Document Processing
source: antigravity
tags: [typescript, api, ai, llm, gpt, workflow, template, design, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-product
---


# AI Product Development

Every product will be AI-powered. The question is whether you'll build it
right or ship a demo that falls apart in production.

This skill covers LLM integration patterns, RAG architecture, prompt
engineering that scales, AI UX that users trust, and cost optimization
that doesn't bankrupt you.

## Principles

- LLMs are probabilistic, not deterministic | Description: The same input can give different outputs. Design for variance.
Add validation layers. Never trust output blindly. Build for the
edge cases that will definitely happen. | Examples: Good: Validate LLM output against schema, fallback to human review | Bad: Parse LLM response and use directly in database
- Prompt engineering is product engineering | Description: Prompts are code. Version them. Test them. A/B test them. Document them.
One word change can flip behavior. Treat them with the same rigor as code. | Examples: Good: Prompts in version control, regression tests, A/B testing | Bad: Prompts inline in code, changed ad-hoc, no testing
- RAG over fine-tuning for most use cases | Description: Fine-tuning is expensive, slow, and hard to update. RAG lets you add
knowledge without retraining. Start with RAG. Fine-tune only when RAG
hits clear limits. | Examples: Good: Company docs in vector store, retrieved at query time | Bad: Fine-tuned model on company data, stale after 3 months
- Design for latency | Description: LLM calls take 1-30 seconds. Users hate waiting. Stream responses.
Show progress. Pre-compute when possible. Cache aggressively. | Examples: Good: Streaming response with typing indicator, cached embeddings | Bad: Spinner for 15 seconds, then wall of text appears
- Cost is a feature | Description: LLM API costs add up fast. At scale, inefficient prompts bankrupt you.
Measure cost per query. Use smaller models where possible. Cache
everything cacheable. | Examples: Good: GPT-4 for complex tasks, GPT-3.5 for simple ones, cached embeddings | Bad: GPT-4 for everything, no caching, verbose prompts

## Patterns

### Structured Output with Validation

Use function calling or JSON mode with schema validation

**When to use**: LLM output will be used programmatically

import { z } from 'zod';

const schema = z.object({
  category: z.enum(['bug', 'feature', 'question']),
  priority: z.number().min(1).max(5),
  summary: z.string().max(200)
});

const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: prompt }],
  response_format: { type: 'json_object' }
});

const parsed = schema.parse(JSON.parse(response.content));

### Streaming with Progress

Stream LLM responses to show progress and reduce perceived latency

**When to use**: User-facing chat or generation features

const stream = await openai.chat.completions.create({
  model: 'gpt-4',
  messages,
  stream: true
});

for await (const chunk of stream) {
  const content = chunk.choices[0]?.delta?.content;
  if (content) {
    yield content; // Stream to client
  }
}

### Prompt Versioning and Testing

Version prompts in code and test with regression suite

**When to use**: Any production prompt

// prompts/categorize-ticket.ts
export const CATEGORIZE_TICKET_V2 = {
  version: '2.0',
  system: 'You are a support ticket categorizer...',
  test_cases: [
    { input: 'Login broken', expected: { category: 'bug' } },
    { input: 'Want dark mode', expected: { category: 'feature' } }
  ]
};

// Test in CI
const result = await llm.generate(prompt, test_case.input);
assert.equal(result.category, test_case.expected.category);

### Caching Expensive Operations

Cache embeddings and deterministic LLM responses

**When to use**: Same queries processed repeatedly

// Cache embeddings (expensive to compute)
const cacheKey = `embedding:${hash(text)}`;
let embedding = await cache.get(cacheKey);

if (!embedding) {
  embedding = await openai.embeddings.create({
    model: 'text-embedding-3-small',
    input: text
  });
  await cache.set(cacheKey, embedding, '30d');
}

### Circuit Breaker for LLM Failures

Graceful degradation when LLM API fails or returns garbage

**When to use**: Any LLM integration in critical path

const circuitBreaker = new CircuitBreaker(callLLM, {
  threshold: 5, // failures
  timeout: 30000, // ms
  resetTimeout: 60000 // ms
});

try {
  const response = await circuitBreaker.fire(prompt);
  return response;
} catch (error) {
  // Fallback: rule-based system, cached response, or human queue
  return fallbackHandler(prompt);
}

### RAG with Hybrid Search

Combine semantic search with keyword matching for better retrieval

**When to use**: Implementing RAG systems

// 1. Semantic search (vector similarity)
const embedding = await embed(query);
const semanticResults = await vectorDB.search(embedding, topK: 20);

// 2. Keyword search (BM25)
const keywordResults = await fullTextSearch(query, topK: 20);

// 3. Rerank combined results
const combined = rerank([...semanticResults, ...keywordResults]);
const topChunks = 
