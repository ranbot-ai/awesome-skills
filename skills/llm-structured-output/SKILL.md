---
name: llm-structured-output
description: Get reliable JSON, enums, and typed objects from LLMs using response_format, tool_use, and schema-constrained decoding across OpenAI, Anthropic, and Google APIs. 
category: AI & Agents
source: antigravity
tags: [python, typescript, api, claude, ai, llm, gpt, workflow, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/llm-structured-output
---


# LLM Structured Output

## What This Skill Does

Extract typed, validated data from LLM API responses instead of parsing free-text. This skill covers the three main approaches: OpenAI's `response_format` with JSON Schema, Anthropic's `tool_use` block for structured extraction, and Google's `responseSchema` in Gemini. You will learn when each approach works, when it breaks, and how to build retry logic around schema validation failures that every production system encounters.

## When to Use This Skill

- The user needs to extract structured data (JSON objects, arrays, enums) from an LLM response
- The user is building a pipeline where LLM output feeds directly into code (database writes, API calls, UI rendering)
- The user asks about `response_format`, `json_mode`, `json_object`, or `json_schema` in OpenAI
- The user asks about using Anthropic's `tool_use` or `tool_result` blocks for data extraction (not for actual tool execution)
- The user asks about Zod schemas with `zodResponseFormat()` from the `openai` npm package
- The user needs to parse LLM output into Pydantic models using `instructor`, `marvin`, or manual validation
- The user is getting malformed JSON, missing fields, or wrong types from LLM responses and needs a fix
- The user asks about `controlled generation`, `constrained decoding`, or `grammar-based sampling` in local models

Do NOT use this skill when:
- The user wants free-form text generation (summaries, essays, chat)
- The user is asking about Zod for form validation or API input validation (use `zod-validation-expert` instead)
- The user needs prompt engineering for better text quality (not structure)
- The user wants to call real external tools/APIs (this skill covers using tool_use as a structured output hack, not actual tool orchestration)

## Core Workflow

1. Identify the target schema. Ask the user what fields they need extracted. Define every field with its type, whether it's required or optional, and valid enum values if applicable. Do not proceed without a concrete schema.

2. Choose the provider-appropriate method:
   - **OpenAI (gpt-4o, gpt-4o-mini):** Use `response_format: { type: "json_schema", json_schema: { ... } }`. This enables Structured Outputs with guaranteed schema conformance via constrained decoding.
   - **Anthropic (Claude):** Define a single tool with the target schema as `input_schema` and set `tool_choice: { type: "tool", name: "extract_data" }`. Claude returns the structured data in the `tool_use` content block.
   - **Google (Gemini):** Use `generationConfig.responseSchema` with a JSON Schema object and set `responseMimeType: "application/json"`.
   - **Local models (llama.cpp, vLLM):** Use GBNF grammars or `--json-schema` flag for constrained decoding at the token level.

3. Write the schema definition in the user's language. For Python, define a Pydantic `BaseModel`. For TypeScript, define a Zod schema and convert it with `zodResponseFormat()`. For raw API calls, write JSON Schema directly.

4. Include field-level descriptions in the schema. Every field should have a `description` string that tells the model what to put there. Models use these descriptions as implicit prompt instructions — a field described as `"The user's sentiment as positive, negative, or neutral"` produces better results than a bare `sentiment: str` with no context.

5. Set the system prompt to reinforce structure. Tell the model its job is data extraction, not conversation. Example: `"You are a data extraction system. Analyze the input and return the requested fields. Do not include explanations outside the JSON structure."`

6. If using OpenAI's `json_schema` mode, set `"strict": true` in the schema definition. This activates constrained decoding where the model can only output tokens that conform to the schema. Without `strict: true`, the model may still produce invalid JSON.

7. If using Anthropic's tool_use approach, extract the structured data from `response.content` by finding the block where `type == "tool_use"` and reading its `input` field. Do not parse the text blocks — the structured data lives exclusively in the tool_use block.

8. Validate the response against the schema in your application code. Even with constrained decoding, validate with Pydantic's `model_validate()` or Zod's `.parse()` before passing data downstream. This catches semantic issues (empty strings, out-of-range numbers) that schema conformance alone cannot prevent.

9. Build a retry loop for validation failures. When validation fails, send the original input plus the failed output and the validation error back to the model with an instruction like `"Your previous output failed validation: {error}. Fix the output."` Cap retries at 3 attempts.

10. Log every structured output call with: the input, the raw response, the parsed result, and any validation errors. When structured output breaks in production, you need these logs to determine whether the failure was a schema design issue, a prompt issue, or 
