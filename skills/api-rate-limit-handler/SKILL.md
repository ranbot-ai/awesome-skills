---
name: api-rate-limit-handler
description: Implement bounded, idempotency-aware API throttling, backoff, and retry handling for 429 and transient 5xx responses. 
category: Document Processing
source: antigravity
tags: [python, typescript, react, api, claude, ai, design, document, stripe, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/api-rate-limit-handler
---


# API Rate Limit Handler

## Overview

A skill for implementing production-grade rate limiting, exponential backoff, and retry strategies when integrating with external APIs. Prevents cascading failures, respects upstream quotas, and keeps your application resilient under load.

## When to Use This Skill

- Use when calling external APIs that enforce rate limits (OpenAI, Stripe, GitHub, etc.)
- Use when you receive 429 Too Many Requests or 5xx errors and need graceful recovery
- Use when building a client that must respect `Retry-After` headers
- Use when designing a system that fans out to multiple API providers
- Use when the user says "handle rate limits", "add retry logic", "backoff strategy", or "don't get throttled"

## How It Works

### Step 1: Classify the response

Determine whether a failed request is retryable or terminal.

| Status | Classification | Action |
|--------|---------------|--------|
| 200-299 | Success | Return response |
| 400, 401, 403, 404 | Terminal client error | Do not retry — fix the request |
| 408, 429 | Retryable (rate limit / timeout) | Retry with backoff |
| 500, 502, 503, 504 | Retryable (server error) | Retry with backoff |

### Step 2: Parse rate limit headers

Always check upstream hints before computing your own delay.

```typescript
function getRetryDelay(
  response: Response,
  attempt: number,
  maxDelayMs = 60_000
): number {
  // Prefer upstream hints
  const retryAfter = response.headers.get("Retry-After");
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) {
      return Math.min(seconds * 1000, maxDelayMs);
    }
    // HTTP-date format
    const date = new Date(retryAfter).getTime();
    if (Number.isFinite(date)) {
      return Math.min(Math.max(0, date - Date.now()), maxDelayMs);
    }
  }

  // GitHub documents x-ratelimit-reset as Unix epoch seconds.
  const githubReset = Number(response.headers.get("x-ratelimit-reset"));
  if (Number.isFinite(githubReset)) {
    return Math.min(
      Math.max(0, githubReset * 1000 - Date.now()),
      maxDelayMs
    );
  }

  // Fallback: capped exponential backoff with full jitter.
  const cap = Math.min(1000 * 2 ** attempt, maxDelayMs);
  return Math.floor(Math.random() * cap);
}
```

Provider-specific reset headers do not share one unit or format. For example,
some APIs return durations while GitHub returns epoch seconds. Parse an
additional header only after checking that provider's current documentation.

### Step 3: Implement the retry loop

```typescript
async function fetchWithRetry(
  url: string,
  options: RequestInit,
  maxRetries = 3,
  maxElapsedMs = 120_000,
  retryNonIdempotent = false
): Promise<Response> {
  const startedAt = Date.now();
  const method = (options.method ?? "GET").toUpperCase();
  const replaySafe = ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"].includes(method)
    || retryNonIdempotent;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const response = await fetch(url, options);

    if (response.ok) return response;

    // Terminal errors — do not retry
    if ([400, 401, 403, 404, 422].includes(response.status)) {
      throw new Error(`Terminal error ${response.status}: ${response.statusText}`);
    }

    if (!replaySafe) {
      throw new Error(
        `${method} was not retried because replay safety was not explicitly established`
      );
    }

    // Retryable — but exhausted attempts
    if (attempt === maxRetries) {
      throw new Error(`Failed after ${maxRetries} retries: ${response.status}`);
    }

    const remaining = maxElapsedMs - (Date.now() - startedAt);
    const delay = Math.min(getRetryDelay(response, attempt), remaining);
    if (delay <= 0) {
      throw new Error(`Retry deadline exceeded after ${maxElapsedMs}ms`);
    }

    // Release the connection before waiting when the body is not needed.
    await response.body?.cancel();
    console.warn(
      `Request failed (${response.status}), retrying in ${Math.round(delay)}ms (attempt ${attempt + 1}/${maxRetries})`
    );
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  throw new Error("Unreachable");
}
```

### Step 4: Add a client-side rate limiter (proactive)

Prevent hitting upstream limits in the first place with a token bucket or sliding window.

```typescript
class TokenBucket {
  private tokens: number;
  private lastRefill: number;
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private maxTokens: number,
    private refillRate: number // tokens per second
  ) {
    this.tokens = maxTokens;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    const ticket = this.queue.then(() => this.acquireOnce());
    this.queue = ticket.catch(() => undefined);
    return ticket;
  }

  private async acquireOnce(): Promise<void> {
    this.refill();
    if (this.tokens < 1) {
      const waitMs = ((1 - this.tokens) / this.refillRate) * 1000;
      await new Promise(resolve =
