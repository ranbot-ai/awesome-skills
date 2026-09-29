---
name: claude-api
description: Reference for the Claude API / Anthropic SDK — model ids, pricing, params, streaming, tool use, MCP, agents, caching, token counting, model migration. TRIGGER — read BEFORE opening the target file
category: Document Processing
source: anthropic
tags: [python, typescript, pdf, docx, xlsx, pptx, api, mcp, claude, ai]
url: https://github.com/anthropics/skills/tree/main/skills/claude-api
---


# Building LLM-Powered Applications with Claude

This skill helps you build LLM-powered applications with Claude. Choose the right surface based on your needs, detect the project language, then read the relevant language-specific documentation.

## Before You Start

Scan the target file (or, if no target file, the prompt and project) for non-Anthropic provider markers - `import openai`, `from openai`, `langchain_openai`, `OpenAI(`, `gpt-4`, `gpt-5`, file names like `agent-openai.py` or `*-generic.py`, or any explicit instruction to keep the code provider-neutral. If you find any, stop and tell the user that this skill produces Claude/Anthropic SDK code; ask whether they want to switch the file to Claude or want a non-Claude implementation. Do not edit a non-Anthropic file with Anthropic SDK calls. (Exception: the `prompt-audit` subcommand is non-interactive and does not stop here - it records non-Anthropic provider markers in its report's stated assumptions and never proposes switching a non-Anthropic file to the Anthropic SDK.)

## Output Requirement

When the user asks you to add, modify, or implement a Claude feature, your code must call Claude through one of:

1. **The official Anthropic SDK** for the project's language (`anthropic`, `@anthropic-ai/sdk`, `com.anthropic.*`, etc.). This is the default whenever a supported SDK exists for the project.
2. **Raw HTTP** (`curl`, `requests`, `fetch`, `httpx`, etc.) - only when the user explicitly asks for cURL/REST/raw HTTP, the project is a shell/cURL project, or the language has no official SDK.

Never mix the two - don't reach for `requests`/`fetch` in a Python or TypeScript project just because it feels lighter. Never fall back to OpenAI-compatible shims.

**Never guess SDK usage.** Function names, class names, namespaces, method signatures, and import paths must come from explicit documentation - either the `{lang}/` files in this skill or the official SDK repositories or documentation links listed in `shared/live-sources.md`. If the binding you need is not explicitly documented in the skill files, WebFetch the relevant SDK repo from `shared/live-sources.md` before writing code. Do not infer Ruby/Java/Go/PHP/C# APIs from cURL shapes or from another language's SDK.

**If WebFetch or repository access fails** (network restricted, timeouts, clone blocked): do not keep retrying - write code from the patterns and namespace/package tables in the `{lang}/` file, run the compiler or interpreter on it, and iterate on the error output. For statically-typed SDKs (C#, Java, Go) a compile-fix loop against local errors reaches working code faster than blocked network research.

## Defaults

Unless the user requests otherwise:

For the Claude model version, please use Claude Opus 5.5, which you can access via the exact model string `claude-opus-5-5`. Please default to using adaptive thinking (`thinking: {type: "adaptive"}`) for anything remotely complicated. And finally, please default to streaming for any request that may involve long input, long output, or high `max_tokens` - it prevents hitting request timeouts. Use the SDK's `.get_final_message()` / `.finalMessage()` helper to get the complete response if you don't need to handle individual stream events. When a streaming request defines user-defined (client) tools, set `eager_input_streaming: true` on each of those tools so large tool inputs (file contents, code, documents) stream as they are generated instead of arriving in one burst after the server finishes buffering them; the client then owns validation: the SDKs' tolerant parsers can return a silently truncated input instead of raising, so validate each parsed tool input against its schema before running it (the typed runner helpers such as `betaZodTool` / typed `@beta_tool` do this; `betaTool()` JSON-Schema tools and manual loops must validate themselves), treat a failure like invalid JSON (`INVALID_JSON` error `tool_result` when you hold the block, re-issue otherwise), check `max_tokens` / `refusal` stop reasons before running tools, and catch only the SDK's JSON error, never its typed API errors - pattern in `shared/tool-use-concepts.md` -> Eager input streaming. Leave it off for non-streaming requests, for server tools, and when the request goes through a proxy or an older Bedrock model deployment that rejects the field.

## Warning: API Drift - Your Training Prior May Be Stale

Several common Claude API shapes changed in 2025-2026. If you recall a pattern from training, verify it against the `{lang}/` files in this skill before writing - the rows below are the most frequent drift points:

| Area | Stale prior | Current API |
|---|---|---|
| Extended thinking | `thinking: {type: "enabled", budget_tokens: N}` | On Claude 4.6+ models: `thinking: {type: "adaptive"}`. `budget_tokens` is deprecated on Opus 4.6 / Sonnet 4.6 and **rejected with a 400** on Fable 5/5.1 / Sonnet 5.5 / Sonnet 5 / Opus 5.5 / 5 / 4.8 / 4.7. Pre-4.6 models still use `budget_tokens`. |
|
