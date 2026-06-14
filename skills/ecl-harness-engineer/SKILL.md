---
name: ecl-harness-engineer
description: Create or audit ECL Agent Harness infrastructure: AGENTS.md, change tracking, repository guidance, lint checks, CI gates, and agent handoff docs. 
category: AI & Agents
source: antigravity
tags: [python, typescript, node, markdown, api, claude, ai, agent, llm, automation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ecl-harness-engineer
---


# ECL Harness Engineer
Design and create Harness Engineering infrastructure so AI agents can work reliably in a codebase.

> **Core Philosophy**: "Intelligence without infrastructure is just a demo." The Agent Harness is the Operating System — the LLM is just the CPU. The repository becomes the single source of truth — if an agent can't see it in context, it doesn't exist.

## When to Use This Skill

- Use when a repository needs AI-agent collaboration infrastructure such as `AGENTS.md`, `docs/ECL.md`, `docs/STATUS.md`, harness change tracking, or mechanical validation gates.
- Use when auditing an existing Agent Harness for missing ECL lifecycle docs, change templates, lint checks, environment contracts, or CI integration.
- Use when converting repeated agent workflow failures into repository-local documentation, tests, lint rules, or lightweight auto-evolution checks.
- Do not use for ordinary business feature implementation unless the requested work is specifically about creating or improving the repository harness.

## Limitations

- This skill creates or audits harness infrastructure; it does not replace product requirements, implementation planning, code review, or release approval for the target project.
- The generated ECL docs, linters, scripts, and CI examples must be adapted to the repository's actual stack, security model, and existing contributor workflow before enforcement.
- Auto-evolve recommendations are guidance only. Apply harness changes through normal review, validation, and rollback discipline instead of accepting them as autonomous policy changes.

## Unified Workflow

This skill follows a single unified workflow regardless of project state (empty, existing code, or existing harness). The core idea: **detect the gap between current state and target state, then fill it**.

Default to a **core ECL harness**. Core includes lightweight auto-evolve threshold checking:
closed changes are counted, a pending evolution note is generated when the threshold is reached,
and Codex applies harness improvements only through evidence, validation, scoring, and rollback.
Advanced agent-platform capabilities such as eval datasets, execution traces, durable state,
checkpoints, long-term memory, and metrics remain optional profiles only when the user explicitly
asks for agent evaluation, observability, resumable execution, or long-term memory.

This skill improves the target repository's agent harness. It does **not** implement ordinary
business features, replace the coding agent's plan mode, or create a separate requirements product.
Plan mode is useful for live discussion; ECL artifacts are the repository record that later agents,
linters, CI, and archive history can inspect.

1. **Quick Detection + Intent Confirmation** — what exists, what already passes, and what the user wants.
2. **Analysis** — architecture, harness state, environment, and project identity.
3. **Intake Review + Delta Synthesis** — classify small vs structured work, support requirement-first
   and plan-first inputs, and compute exactly what to create or update.
4. **Creation/Update** — docs, status handoff, linters, ECL/change scripts, environment config, and CI.
5. **Verification + Handoff** — run checks, attribute failures, update STATUS.md, trigger auto-evolve checks, and summarize results.

---

## Phase 1: Quick Detection + Intent Confirmation

**Goal**: In under 5 minutes, understand project state and user intent.

### 1.1 Project State Detection

Run this quick scan:

```bash
# Count files
file_count=$(find . -type f ! -path './.git/*' ! -path './node_modules/*' ! -path './vendor/*' 2>/dev/null | wc -l)
code_files=$(find . -type f \( -name "*.go" -o -name "*.ts" -o -name "*.js" -o -name "*.py" -o -name "*.rs" \) ! -path './.git/*' ! -path './node_modules/*' ! -path './vendor/*' 2>/dev/null | wc -l)

# Check harness components
has_agents_md=$(test -f AGENTS.md && echo "yes" || echo "no")
has_architecture=$(test -f docs/ARCHITECTURE.md && echo "yes" || echo "no")
has_linters=$(ls scripts/lint-* 2>/dev/null | wc -l)
has_harness_dir=$(test -d harness && echo "yes" || echo "no")
has_ecl_doc=$(test -f docs/ECL.md && echo "yes" || echo "no")
has_changes_dir=$(test -d harness/changes && echo "yes" || echo "no")
has_change_templates=$(test -d harness/templates/change && echo "yes" || echo "no")
has_change_script=$(ls scripts/harness-change.* 2>/dev/null | wc -l)
has_evolve_script=$(ls scripts/harness-evolve.* 2>/dev/null | wc -l)
has_ecl_lint=$(ls scripts/lint-ecl.* 2>/dev/null | wc -l)
has_encoding_lint=$(ls scripts/lint-encoding.* 2>/dev/null | wc -l)
has_makefile=$(test -f Makefile && echo "yes" || echo "no")
has_package_json=$(test -f package.json && echo "yes" || echo "no")

# Detect tech stack
if test -f go.mod; then TECH="Go"
elif test -f package.json; then TECH="TypeScript/Node.js"
elif test -f requirements.txt || test -f pyproject.toml; then TECH="Python"
else TECH="Unknown"
fi
```

### 1.2 Classify Project State

Based on d
