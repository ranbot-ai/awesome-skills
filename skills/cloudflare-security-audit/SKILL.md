---
name: cloudflare-security-audit
description: Audit authorized codebases for exploitable vulnerabilities using scoped reconnaissance, adversarial review, validation, and structured reporting. 
category: Security & Systems
source: antigravity
tags: [api, ai, agent, llm, workflow, design, security, vulnerability, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cloudflare-security-audit
---



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

Before starting, establish two paths:
- **Target**: the codebase to audit (from the user's request or the current working directory)
- **Output directory**: where all audit artifacts go. Ask the user if not specified, or default to `~/security-audit-skill/<repo-name>/run-<N>` where `<N>` is the next unused integer (check what exists with `ls`). Create it if it doesn't exist. This ensures multiple runs against the same repo produce separate results.

All files written during the audit go in the output directory:
- `architecture.md` — Phase 1 output, fed into Phase 2 agent prompts
- `REPORT.md` — human-readable report (Phase 4)
- `FINDINGS-DETAIL.md` — detailed data flows for MEDIUM+ findings (Phase 4)
- `findings.json` — machine-readable structured output (Phase 5)

Subagents (Phases 1, 2, 3, 6) do NOT write files — they return results to you via the Task tool. You are responsible for writing all files to the output directory.

### Coverage and prior runs

Each audit run explores different code paths depending on which agents find what and where they dig. No single run finds everything. Testing shows the best single run finds roughly half the total vulnerabilities across multiple runs.

**If prior runs exist** for the same repo (check `~/security-audit-skill/<repo-name>/`), read their `findings.json` files before starting Phase 2. Use them to:
1. **Skip known findings** — don't waste agents re-discovering the same status bypass. Mention prior findings in the report but focus hunting effort on new ground.
2. **Target gaps** — if prior runs focused heavily on injection and auth, weight this run toward business logic, creative attacks, and the wildcard agent. If prior runs missed public endpoints, focus there.
3. **Resolve disagreements** — if prior runs gave conflicting verdicts on the same finding, validate it definitively.

Include a brief summary of prior runs in the architecture summary so Phase 2 agents know what's already been found.

**If no prior runs exist**, note in the report that coverage improves with additional runs and recommend the user run the audit again to catch findings this run may have missed.

## Core Principles

### Only report what you can exploit

Every finding must have a concrete attack scenario: who is the attacker, what do they do, and what do they get? "An attacker could theoretically..." is not a finding. "Send this request, get this result" is.

### Confirm dynamically when you can

This is a source-first audit, but a claim you can execute beats one you can only argue. Where the target is locally buildable — a parser, a library, a CLI, a native component — build and run it: reproduce the crash, run the payload, diff the two parsers on the same bytes. Better still, **extract the suspect code into a minimal standalone harness** and test the hypothesis in isolation — fuzz the one function, feed it the crafted input, watch what it does. Where confirmation needs infrastructure you don't have — a proxy chain, a live cache, production auth — you cannot confirm from source alone: mark it "requires deployment testing" and do not report it as confirmed. Dynamic evidence is what resolves the memory-safety and request-framing classes that static reading leaves ambiguous.

### Determine the baseline dynamically

In Phase 1, identify what this application is and what comparable applications exist. Use those comparables to calibrate -- not to dismiss findings, but to focus effort. If the comparable has the same pattern and it's been exploited there, that's a STRONGE
