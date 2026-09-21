---
name: apify-generate-output-schema
description: Generate output schemas (dataset_schema.json, output_schema.json, key_value_store_schema.json) for an Apify Actor by analyzing its source code. Use when creating or updating Actor output schemas. 
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, pdf, api, ai, agent, workflow, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-generate-output-schema
---

## When to Use
- Use when this upstream workflow matches the user's stated goal.
- Use when the task requires the procedures documented in this skill.

# Generate Actor output schema

You are generating output schema files for an Apify Actor. The output schema tells Apify Console how to display run results. You will analyze the Actor's source code, create `dataset_schema.json`, `output_schema.json`, and `key_value_store_schema.json` (if the Actor uses key-value store), and update `actor.json`.

## Core principles

- **Analyze code first**: Read the Actor's source to understand what data it actually pushes to the dataset — never guess
- **Every field is nullable**: APIs and websites are unpredictable — always set `"nullable": true`
- **Anonymize examples**: Never use real user IDs, usernames, or personal data in examples
- **Verify against code**: If TypeScript types exist, cross-check the schema against both the type definition AND the code that produces the values
- **Reuse existing patterns**: Before generating schemas, check if other Actors in the same repository already have output schemas — match their structure, naming conventions, description style, and formatting
- **Don't reinvent the wheel**: Reuse existing type definitions, interfaces, and utilities from the codebase instead of creating duplicate definitions

---

## Phase 1: Discover Actor structure

**Goal**: Locate the Actor and understand its output

Initial request: $ARGUMENTS

**Actions**:
1. Create todo list with all phases
2. Find the `.actor/` directory containing `actor.json`
3. Read `actor.json` to understand the Actor's configuration
4. Check if `dataset_schema.json`, `output_schema.json`, and `key_value_store_schema.json` already exist
5. **Search for existing schemas in the repository**: Look for other `.actor/` directories or schema files (e.g., `**/dataset_schema.json`, `**/output_schema.json`, `**/key_value_store_schema.json`) to learn the repo's conventions — match their description style, field naming, example formatting, and overall structure
6. Find all places where data is pushed to the dataset:
   - **JavaScript/TypeScript**: Search for `Actor.pushData(`, `dataset.pushData(`, `Dataset.pushData(`
   - **Python**: Search for `Actor.push_data(`, `dataset.push_data(`, `Dataset.push_data(`
7. Find all places where data is stored in the key-value store:
   - **JavaScript/TypeScript**: Search for `Actor.setValue(`, `keyValueStore.setValue(`, `KeyValueStore.setValue(`
   - **Python**: Search for `Actor.set_value(`, `key_value_store.set_value(`, `KeyValueStore.set_value(`
8. Find output type definitions — **reuse them directly** instead of recreating from scratch:
   - **TypeScript**: Look for output type interfaces/types (e.g., in `src/types/`, `src/types/output.ts`). If an interface or type already defines the output shape, derive the schema fields from it — do not create a parallel definition
   - **Python**: Look for TypedDict, dataclass, or Pydantic model definitions. Use the existing field names, types, and docstrings as the source of truth
9. Check for existing shared schema utilities or helper functions in the codebase that handle schema generation or validation — reuse them rather than creating new logic
10. If inline `storages.dataset` or `storages.keyValueStore` config exists in `actor.json`, note it for migration

Present findings to user: list all discovered dataset output fields, key-value store keys, their types, and where they come from.

---

## Phase 2: Generate `dataset_schema.json`

**Goal**: Create a complete dataset schema with field definitions and display views

### File structure

```json
{
    "actorSpecification": 1,
    "fields": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            // ALL output fields here — every field the Actor can produce,
            // not just the ones shown in the overview view
        },
        "required": [],
        "additionalProperties": true
    },
    "views": {
        "overview": {
            "title": "Overview",
            "description": "Most important fields at a glance",
            "transformation": {
                "fields": [
                    // 8-12 most important field names
                ]
            },
            "display": {
                "component": "table",
                "properties": {
                    // Display config for each overview field
                }
            }
        }
    }
}
```

### Consistency with existing schemas

If existing output schemas were found in the repository during Phase 1 (step 5), follow their conventions:
- Match the **description writing style** (sentence case vs. lowercase, period vs. no period, etc.)
- Match the **field naming convention** (camelCase vs. snake_case) — this must also match the actual keys produced by the Actor code
- Match the **example value style** (e.g., date formats, URL patterns, placeholder names)
- Match t
