---
name: context-window-management
description: Strategies for managing LLM context windows including summarization, trimming, routing, and avoiding context rot 
category: Development & Code Tools
source: antigravity
tags: [typescript, api, claude, ai, llm, workflow, design, langchain, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/context-window-management
---


# Context Window Management

Strategies for managing LLM context windows including summarization, trimming, routing, and avoiding context rot

## Capabilities

- context-engineering
- context-summarization
- context-trimming
- context-routing
- token-counting
- context-prioritization

## Prerequisites

- Knowledge: LLM fundamentals, Tokenization basics, Prompt engineering
- Skills_recommended: prompt-engineering

## Scope

- Does_not_cover: RAG implementation details, Model fine-tuning, Embedding models
- Boundaries: Focus is context optimization, Covers strategies not specific implementations

## Ecosystem

### Primary_tools

- tiktoken - OpenAI's tokenizer for counting tokens
- LangChain - Framework with context management utilities
- Claude API - 200K+ context with caching support

## Patterns

These are incomplete architectural sketches with application-defined helpers/types. Model IDs and context limits are historical; discover supported models and use their tokenizer/counting API (tiktoken is not a universal Claude tokenizer). Preserve system/developer boundaries and user constraints verbatim; never silently truncate them to a percentage budget. Keep retrieved text and summaries clearly marked as data. Preserve chronological/tool-call relationships, recount the final serialized request including tools and reserved output, and fail/reduce optional history if it still exceeds the limit. Importance ordering alone must not scramble dependent messages.

### Tiered Context Strategy

Different strategies based on context size

**When to use**: Building any multi-turn conversation system

```typescript
interface ContextTier {
    maxTokens: number;
    strategy: 'full' | 'summarize' | 'rag';
    model: string;
}

const TIERS: ContextTier[] = [
    { maxTokens: 8000, strategy: 'full', model: 'claude-3-haiku' },
    { maxTokens: 32000, strategy: 'full', model: 'claude-3-5-sonnet' },
    { maxTokens: 100000, strategy: 'summarize', model: 'claude-3-5-sonnet' },
    { maxTokens: Infinity, strategy: 'rag', model: 'claude-3-5-sonnet' }
];

async function selectStrategy(messages: Message[]): Promise<ContextTier> {
    const tokens = await countTokens(messages);

    for (const tier of TIERS) {
        if (tokens <= tier.maxTokens) {
            return tier;
        }
    }
    return TIERS[TIERS.length - 1];
}

async function prepareContext(messages: Message[]): Promise<PreparedContext> {
    const tier = await selectStrategy(messages);

    switch (tier.strategy) {
        case 'full':
            return { messages, model: tier.model };

        case 'summarize':
            const summary = await summarizeOldMessages(messages);
            return { messages: [summary, ...recentMessages(messages)], model: tier.model };

        case 'rag':
            const relevant = await retrieveRelevant(messages);
            return { messages: [...relevant, ...recentMessages(messages)], model: tier.model };
    }
}
```

### Serial Position Optimization

Place important content at start and end

**When to use**: Constructing prompts with significant context

```typescript
// LLMs weight beginning and end more heavily
// Structure prompts to leverage this

function buildOptimalPrompt(components: {
    systemPrompt: string;
    criticalContext: string;
    conversationHistory: Message[];
    currentQuery: string;
}): string {
    // START: System instructions (always first)
    const parts = [components.systemPrompt];

    // CRITICAL CONTEXT: Right after system (high primacy)
    if (components.criticalContext) {
        parts.push(`## Key Context\n${components.criticalContext}`);
    }

    // MIDDLE: Conversation history (lower weight)
    // Summarize if long, keep recent messages full
    const history = components.conversationHistory;
    if (history.length > 10) {
        const oldSummary = summarize(history.slice(0, -5));
        const recent = history.slice(-5);
        parts.push(`## Earlier Conversation (Summary)\n${oldSummary}`);
        parts.push(`## Recent Messages\n${formatMessages(recent)}`);
    } else {
        parts.push(`## Conversation\n${formatMessages(history)}`);
    }

    // END: Current query (high recency)
    // Restate critical requirements here
    parts.push(`## Current Request\n${components.currentQuery}`);

    // FINAL: Reminder of key constraints
    parts.push(`Remember: ${extractKeyConstraints(components.systemPrompt)}`);

    return parts.join('\n\n');
}
```

### Intelligent Summarization

Summarize by importance, not just recency

**When to use**: Context exceeds optimal size

```typescript
interface MessageWithMetadata extends Message {
    importance: number;  // 0-1 score
    hasCriticalInfo: boolean;  // User preferences, decisions
    referenced: boolean;  // Was this referenced later?
}

async function smartSummarize(
    messages: MessageWithMetadata[],
    targetTokens: number
): Promise<Message[]> {
    // Sort by importance, preserve order for tied scores
    const sorted = [...me
