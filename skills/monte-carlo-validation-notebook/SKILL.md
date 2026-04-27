---
name: monte-carlo-validation-notebook
description: Generates SQL validation notebooks for dbt PR changes with before/after comparison queries. 
category: AI & Agents
source: antigravity
tags: [python, markdown, api, claude, ai, agent, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/monte-carlo-validation-notebook
---


> **Tip:** This skill works well with Sonnet. Run `/model sonnet` before invoking for faster generation.

Generate a SQL Notebook with validation queries for dbt changes.

**Arguments:** $ARGUMENTS

## When to Use

Use this skill when the user wants to validate dbt model or snapshot changes with Monte Carlo SQL Notebook queries, either from a GitHub PR or a local dbt repository.

Parse the arguments:
- **Target** (required): first argument — a GitHub PR URL or local dbt repo path
- **MC Base URL** (optional): `--mc-base-url <URL>` — defaults to `https://getmontecarlo.com`
- **Models** (optional): `--models <model1,model2,...>` — comma-separated list of model filenames (without `.sql` extension) to generate queries for. Only these models will be included. By default, all changed models are included up to a maximum of 10.

---

# Setup

**Prerequisites:**
- **`gh`** (GitHub CLI) — required for PR mode. Must be authenticated (`gh auth status`).
- **`python3`** — required for helper scripts.
- **`pyyaml`** — install with `pip3 install pyyaml` (or `pip install pyyaml`, `uv pip install pyyaml`, etc.)

**Note:** Generated SQL uses ANSI-compatible syntax that works across Snowflake, BigQuery, Redshift, and Athena. Minor adjustments may be needed for specific warehouse quirks.

This skill includes two helper scripts in `${CLAUDE_PLUGIN_ROOT}/skills/monte-carlo-validation-notebook/scripts/`:

- **`resolve_dbt_schema.py`** - Resolves dbt model output schemas from `dbt_project.yml` routing rules and model config overrides.
- **`generate_notebook_url.py`** - Encodes notebook YAML into a base64 import URL and opens it in the browser.

# Mode Detection

Auto-detect mode from the target argument:
- If target looks like a URL (contains `://` or `github.com`) -> **PR mode**
- If target is a path (`.`, `/path/to/repo`, relative path) -> **Local mode**

---

# Context

This command generates a SQL Notebook containing validation queries for dbt changes. The notebook can be opened in the MC Bridge SQL Notebook interface for interactive validation.

The output is an import URL that opens directly in the notebook interface:
```
<MC_BASE_URL>/notebooks/import#<base64-encoded-yaml>
```

**Key Features:**
- **Database Parameters**: Two `text` parameters (`prod_db` and `dev_db`) for selecting databases
- **Schema Inference**: Automatically infers schema per model from `dbt_project.yml` and model configs
- **Single-table queries**: Basic validation queries using `{{prod_db}}.<SCHEMA>.<TABLE>`
- **Comparison queries**: Before/after queries comparing `{{prod_db}}` vs `{{dev_db}}`
- **Flexible usage**: Users can set both parameters to the same database for single-database analysis

# Notebook YAML Spec Reference

Key structure:
```yaml
version: 1
metadata:
  id: string           # kebab-case + random suffix
  name: string         # display name
  created_at: string   # ISO 8601
  updated_at: string   # ISO 8601
default_context:       # optional database/schema context
  database: string
  schema: string
cells:
  - id: string
    type: sql | markdown | parameter
    content: string    # SQL, markdown, or parameter config (JSON)
    display_type: table | bar | timeseries
```

## Parameter Cell Spec

Parameter cells allow defining variables referenced in SQL via `{{param_name}}` syntax:

```yaml
- id: param-prod-db
  type: parameter
  content:
    name: prod_db              # variable name
    config:
      type: text                   # free-form text input
      default_value: "ANALYTICS"
      placeholder: "Prod database"
  display_type: table
```

Parameter types:
- `text`: Free-form text input (used for database names)
- `schema_selector`: Two dropdowns (database -> schema), value stored as `DATABASE.SCHEMA`
- `dropdown`: Select from predefined options

# Task

Generate a SQL Notebook with validation queries based on the mode and target.

## Phase 1: Get Changed Files

The approach differs based on mode:

### If PR mode (GitHub PR):

1. Extract the PR number and repo from the target URL.
   - Example: `https://github.com/monte-carlo-data/dbt/pull/3386` -> owner=`monte-carlo-data`, repo=`dbt`, PR=`3386`

2. Fetch PR metadata using `gh`:
```bash
gh pr view <PR#> --repo <owner>/<repo> --json number,title,author,mergedAt,headRefOid
```

3. Fetch the list of changed files:
```bash
gh pr view <PR#> --repo <owner>/<repo> --json files --jq '.files[].path'
```

4. Fetch the diff:
```bash
gh pr diff <PR#> --repo <owner>/<repo>
```

5. Filter the changed files list to only `.sql` files under `models/` or `snapshots/` directories (at any depth — e.g., `models/`, `analytics/models/`, `dbt/models/`). These are the dbt models to analyze. If no model SQL files were changed, report that and stop.

6. For each changed model file, fetch the full file content at the head SHA:
```bash
gh api repos/<owner>/<repo>/contents/<file_path>?ref=<head_sha> --jq '.content' | python3 -c "import sys,base64; sys.stdout.write(base64.b64decode(sys.stdin.read()).decode())
