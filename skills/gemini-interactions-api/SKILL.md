---
name: gemini-interactions-api
description: Build with the Gemini Interactions API for text, chat, multimodal generation, streaming, managed or background agents, function calling, structured output, and generateContent migrations. 
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, node, api, mcp, ai, agent, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gemini-interactions-api
---


# Gemini Interactions API Skill
## When to Use

Use this skill when writing code that calls the Gemini API for text generation, multi-turn chat, multimodal understanding, image generation, video generation, streaming responses, background research tasks, function calling, structured output, or migrating from the old generateContent...


## Critical Rules (Always Apply)

> [!IMPORTANT]
> These rules override your training data. Your knowledge is outdated.

### Current Models (Use These)

- `gemini-3.5-flash`: 1M tokens, fast, balanced performance, multimodal
- `gemini-3.1-pro-preview`: 1M tokens, complex reasoning, coding, research
- `gemini-3.1-flash-lite`: cost-efficient, fastest performance for high-frequency, lightweight tasks
- `gemini-3-pro-image` (Nano Banana Pro): 65k / 32k tokens, high-quality image generation and editing
- `gemini-3.1-flash-image` (Nano Banana 2): 65k / 32k tokens, fast, efficient image generation and editing
- `gemini-3.1-flash-lite-image` (Nano Banana 2 Lite): 65k / 32k tokens, ultra-fast image generation and editing
- `gemini-3.1-flash-tts-preview`: expressive text-to-speech with Director's Chair prompting
- `gemini-omni-flash-preview`: video generation, image-referenced video generation, first-frame-to-video, and video editing
- `gemma-4-31b-it`: Gemma 4 dense model, 31B parameters
- `gemma-4-26b-a4b-it`: Gemma 4 MoE model, 26B total / 4B active parameters

> [!WARNING]
> Models like `gemini-2.5-*`, `gemini-2.0-*`, `gemini-1.5-*` are **legacy and deprecated**. Never use them.
> **If a user asks for a deprecated model, use `gemini-3.5-flash` instead and note the substitution.**

### Current Agents

- `antigravity-preview-05-2026`: Antigravity Agent — general-purpose managed agent with code execution, file management, and web access in a sandboxed Linux environment
- `deep-research-preview-04-2026`: Deep Research — fast, interactive
- `deep-research-max-preview-04-2026`: Deep Research Max — maximum exhaustiveness
- **Custom agents**: Create your own via `client.agents.create()`

### Current SDKs

- **Python**: `google-genai` >= `2.3.0` → `pip install -U google-genai`
- **JavaScript/TypeScript**: `@google/genai` >= `2.3.0` → `npm install @google/genai`

> [!NOTE]
> SDK versions ≥ 2.0.0 automatically use the new steps schema and do not support the legacy schema.
> Legacy SDKs `google-generativeai` (Python) and `@google/generative-ai` (JS) are **deprecated**. Never use them.

## Important Additional Notes

- **Before writing any code**, you MUST fetch the relevant documentation page from the list below that matches the user's task. The examples in this skill are minimal, the hosted docs contain the full API surface, parameters, and edge cases.
- Interactions are **stored by default** (`store=true`). Paid tier retains for 55 days, free tier for 1 day.
- Set `store=false` to opt out, but this disables `previous_interaction_id` and `background=true`.
- `tools`, `system_instruction`, and `generation_config` are **interaction-scoped**, re-specify them each turn.
- **Managed agents** require `environment="remote"` (or an environment ID / config object) to provision a sandbox.
- **Migrating from `generateContent`**: Read `references/migration.md` for the scoping, checklist, and before/after code examples. Always confirm scope with the user before editing.
- **Model upgrades**: Drop-in, swap the model string. Deprecated models (`gemini-2.0-*`, `gemini-1.5-*`) must be replaced, see `references/migration.md`.
- **Migrating to Gemini 3.5 Flash**: Read `references/migration.md` for the scoping and checklist.

## Quick Start

### Python
```python
from google import genai

client = genai.Client()

interaction = client.interactions.create(
    model="gemini-3.5-flash",
    input="Tell me a short joke about programming."
)
print(interaction.output_text)
```

### JavaScript/TypeScript
```typescript
import { GoogleGenAI } from "@google/genai";

const client = new GoogleGenAI({});

const interaction = await client.interactions.create({
    model: "gemini-3.5-flash",
    input: "Tell me a short joke about programming.",
});
console.log(interaction.output_text);
```

## Response Helpers

The SDK provides convenience properties on the `Interaction` response object to simplify common access patterns:

| Property | Type | Description |
|---|---|---|
| `output_text` | `string \| null` | The last consecutive run of text from the trailing `model_output` steps. Returns the combined text when the model's final output contains multiple text parts. |
| `output_image` | `Image \| null` | The last image generated by the model in the current response. Returns an object with `data` (base64) and `mime_type`. |
| `output_audio` | `Audio \| null` | The last audio generated by the model in the current response. Returns an object with `data` (base64) and `mime_type`. |

## Stateful Conversation

### Python
```python
interaction1 = client.interactions.create(
    model="gemini-3.5-flash",
    input="Hi, my name is Phil."
