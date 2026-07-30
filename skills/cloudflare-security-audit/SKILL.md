---
name: cloudflare-security-audit
description: Audit authorized codebases for exploitable vulnerabilities using scoped reconnaissance, adversarial review, validation, and structured reporting. 
category: Security & Systems
source: antigravity
tags: [api, ai, agent, llm, workflow, design, security, vulnerability, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cloudflare-security-audit
---


> **⚠️ AUTHORIZED USE ONLY**
> This skill is for educational purposes or authorized security assessments only.
> You must have explicit, written permission from the system owner before using this tool.
> Misuse of this tool is illegal and strictly prohibited.

> **Mandatory confirmation gate**
> Before running any command that probes, exploits, changes, persists on, extracts data from, or attempts credential access against a target:
> 1. Ask the user to state the exact target URL, IP, account, or resource.
> 2. Ask the user to confirm written authorization and the permitted scope.
> 3. Show the exact command(s) and explain their expected effect.
> 4. Wait for explicit confirmation in the current conversation.
>
> Without that confirmation, remain read-only and provide defensive guidance only. Prefer a sandbox, disposable VM, or controlled lab.

# Security Audit

> [!WARNING]
> **Authorized Use Only.** Audit only code and systems the user owns or is explicitly authorized to assess. Keep testing inside the approved scope and avoid destructive exploitation.

## Example

```text
User: Audit this repository for authorization bypasses and injection paths. Keep testing local and non-destructive.
Agent: I will confirm the repository scope, map trust boundaries, validate each candidate, and report only reproducible findings.
```

You are a security auditor. Your job is to find **exploitable vulnerabilities with real impact**.

## When to Use

Use this skill when asked to perform a security audit, find security bugs, do a security review, audit for vulnerabilities, or pen-test a codebase. Activate it for web apps, APIs, services, CLI tools, libraries, daemons, and more.

## Platform terminology

This skill is agent-neutral. In the methodology:

- **Task tool** means the coding agent's delegation or sub-agent mechanism.
- **`research` agent** means a delegated agent optimized for focused codebase exploration and factual verification.
- **`general` agent** means a delegated agent that can investigate broadly and spawn focused research agents.
- **`subagent_type`** means the equivalent delegated-agent role supported by the current platform.

Use the platform's equivalent capabilities while preserving the specified roles, parallelism, prompts, and independence boundaries.

## Setup

Before starting, establish two paths and one target identity:
- **Target**: the codebase to audit (from the user's request or the current working directory)
- **Target identity**: the canonical physical repository path plus its normalized `origin` owner/repository URL. Hash both values to create a stable target ID; do not key history by repository basename alone.
- **Output directory**: where all audit artifacts go. Ask the user if not specified, or default to `~/security-audit-skill/<target-id>/run-<N>` where `<N>` is the next unused integer. Create it if it doesn't exist. This ensures same-named repositories cannot share audit history.

All files written during the audit go in the output directory:
- `architecture.md` — Phase 1 output, fed into Phase 2 agent prompts
- `REPORT.md` — human-readable report (Phase 4)
- `FINDINGS-DETAIL.md` — detailed data flows for MEDIUM+ findings (Phase 4)
- `findings.json` — machine-readable structured output (Phase 5)
- `target.json` — canonical path, normalized origin, and target ID used to bind this run

Subagents (Phases 1, 2, 3, 6) do NOT write files — they return results to you via the Task tool. You are responsible for writing all files to the output directory.

### Coverage and prior runs

Each audit run explores different code paths depending on which agents find what and where they dig. No single run finds everything. Testing shows the best single run finds roughly half the total vulnerabilities across multiple runs.

**If prior runs exist** for the exact target ID, first require their `target.json` canonical path and normalized origin to match the current target byte-for-byte. Treat missing or mismatched manifests as unrelated and never read or summarize their findings. Do not search or reuse prior runs from a basename-only directory. After that identity check, read matching `findings.json` files before starting Phase 2. Use them to:
1. **Skip known findings** — don't waste agents re-discovering the same status bypass. Mention prior findings in the report but focus hunting effort on new ground.
2. **Target gaps** — if prior runs focused heavily on injection and auth, weight this run toward business logic, creative attacks, and the wildcard agent. If prior runs missed public endpoints, focus there.
3. **Resolve disagreements** — if prior runs gave conflicting verdicts on the same finding, validate it definitively.

Include a brief summary of prior runs in the architecture summary so Phase 2 agents know what's already been found.

**If no prior runs exist**, note in the report that coverage improves with additional runs and recommend the user run the audit again to catch findings this run may have 
