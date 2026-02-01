---
name: context-compression
description: Design and evaluate compression strategies for long-running sessions 
category: Document Processing
source: antigravity
tags: [markdown, api, ai, agent, llm, workflow, template, design, document, presentation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/context-compression
---

# Context Compression Strategies

When agent sessions generate millions of tokens of conversation history, compression becomes mandatory. The naive approach is aggressive compression to minimize tokens per request. The correct optimization target is tokens per task: total tokens consumed to complete a task, including re-fetching costs when compression loses critical information.

## When to Activate

Activate this skill when:
- Agent sessions exceed context window limits
- Codebases exceed context windows (5M+ token systems)
- Designing conversation summarization strategies
- Debugging cases where agents "forget" what files they modified
- Building evaluation frameworks for compression quality

## Core Concepts

Context compression trades token savings against information loss. Three production-ready approaches exist:

1. **Anchored Iterative Summarization**: Maintain structured, persistent summaries with explicit sections for session intent, file modifications, decisions, and next steps. When compression triggers, summarize only the newly-truncated span and merge with the existing summary. Structure forces preservation by dedicating sections to specific information types.

2. **Opaque Compression**: Produce compressed representations optimized for reconstruction fidelity. Achieves highest compression ratios (99%+) but sacrifices interpretability. Cannot verify what was preserved.

3. **Regenerative Full Summary**: Generate detailed structured summaries on each compression. Produces readable output but may lose details across repeated compression cycles due to full regeneration rather than incremental merging.

The critical insight: structure forces preservation. Dedicated sections act as checklists that the summarizer must populate, preventing silent information drift.

## Detailed Topics

### Why Tokens-Per-Task Matters

Traditional compression metrics target tokens-per-request. This is the wrong optimization. When compression loses critical details like file paths or error messages, the agent must re-fetch information, re-explore approaches, and waste tokens recovering context.

The right metric is tokens-per-task: total tokens consumed from task start to completion. A compression strategy saving 0.5% more tokens but causing 20% more re-fetching costs more overall.

### The Artifact Trail Problem

Artifact trail integrity is the weakest dimension across all compression methods, scoring 2.2-2.5 out of 5.0 in evaluations. Even structured summarization with explicit file sections struggles to maintain complete file tracking across long sessions.

Coding agents need to know:
- Which files were created
- Which files were modified and what changed
- Which files were read but not changed
- Function names, variable names, error messages

This problem likely requires specialized handling beyond general summarization: a separate artifact index or explicit file-state tracking in agent scaffolding.

### Structured Summary Sections

Effective structured summaries include explicit sections:

```markdown
## Session Intent
[What the user is trying to accomplish]

## Files Modified
- auth.controller.ts: Fixed JWT token generation
- config/redis.ts: Updated connection pooling
- tests/auth.test.ts: Added mock setup for new config

## Decisions Made
- Using Redis connection pool instead of per-request connections
- Retry logic with exponential backoff for transient failures

## Current State
- 14 tests passing, 2 failing
- Remaining: mock setup for session service tests

## Next Steps
1. Fix remaining test failures
2. Run full test suite
3. Update documentation
```

This structure prevents silent loss of file paths or decisions because each section must be explicitly addressed.

### Compression Trigger Strategies

When to trigger compression matters as much as how to compress:

| Strategy | Trigger Point | Trade-off |
|----------|---------------|-----------|
| Fixed threshold | 70-80% context utilization | Simple but may compress too early |
| Sliding window | Keep last N turns + summary | Predictable context size |
| Importance-based | Compress low-relevance sections first | Complex but preserves signal |
| Task-boundary | Compress at logical task completions | Clean summaries but unpredictable timing |

The sliding window approach with structured summaries provides the best balance of predictability and quality for most coding agent use cases.

### Probe-Based Evaluation

Traditional metrics like ROUGE or embedding similarity fail to capture functional compression quality. A summary may score high on lexical overlap while missing the one file path the agent needs.

Probe-based evaluation directly measures functional quality by asking questions after compression:

| Probe Type | What It Tests | Example Question |
|------------|---------------|------------------|
| Recall | Factual retention | "What was the original error message?" |
| Artifact | File tracking | "Which files have we modified?" |
| Continuation | Task planni
