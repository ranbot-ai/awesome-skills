---
name: agy-auto
description: Configure agy-auto PreToolUse security gate to run Antigravity CLI (agy) unattended with layered policy controls instead of --dangerously-skip-permissions. 
category: AI & Agents
source: antigravity
tags: [python, api, ai, agent, llm, workflow, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agy-auto
---


# agy-auto — Antigravity Auto-Permission & Security Gate

## Overview

`agy-auto` is a PreToolUse hook and security harness for Google Antigravity CLI (`agy`) that supports a reviewed unattended-execution policy without relying on `--dangerously-skip-permissions`. It passes every pending tool call through a multi-layered policy gate: deterministic hard-deny rules, deterministic fast-allow for workspace-scoped and read-only operations, an LLM classifier fallback (Gemini Flash Lite or local llama.cpp), and single-use scoped token approvals with Zero Ambient Authority.

## When to Use This Skill

- Use when running Antigravity CLI (`agy`) unattended or in background agent loops and you want automated tool permissions without exposing system files or credentials.
- Use when you need granular, auditable controls over shell commands, file modifications, and network egress during `agy` workflows.
- Use when setting up a secure pair-programming environment with Antigravity that reduces tool-call exposure within a verified workspace boundary.

## How It Works

### Step 1: Review, Pin, and Install agy-auto

> [!IMPORTANT]
> Because `agy-auto` installs as an active PreToolUse hook on the permission evaluation path, never clone a mutable branch directly into your live plugin directory. Always clone to a temporary staging folder, pin an immutable release tag or commit SHA, and inspect the codebase before making the hook executable.

**Option A: Native Antigravity Plugin (Recommended)**
```bash
# 1. Clone into a temporary review directory and checkout an immutable release tag
git clone https://github.com/onkarbadve/agy-auto.git /tmp/agy-auto-review
cd /tmp/agy-auto-review
git checkout <verified-full-commit-sha>

# 2. Inspect hook.sh and engine/ files before deployment
less hook.sh
python3 -m unittest -v tests/test_engine.py

# 3. Once reviewed and verified, copy to the Antigravity plugin directory and set permissions
# Host activation requires explicit user approval, an existing-config backup,
# and a reviewed non-overwriting installation into the confirmed host path.
```

Only if the exact CLI/hook combination has been verified to fail closed on missing, failed and tampered hooks, and the user explicitly approves this host permission change, configure `toolPermission: "always-proceed"` in `~/.gemini/antigravity-cli/settings.json` so hooks can gate tool calls:
```json
{
  "toolPermission": "always-proceed"
}
```

**Option B: Global Hook via Installer**
```bash
# 1. Clone to an isolated location and pin release
git clone https://github.com/onkarbadve/agy-auto.git ~/.local/share/agy-auto
cd ~/.local/share/agy-auto
git checkout <verified-full-commit-sha>

# 2. Review and run the installer
chmod +x hook.sh
./install.sh                  # registers hook in hooks.json, sets always-proceed, runs smoke tests
```

### Step 2: Policy Evaluation Layers

`agy-auto` evaluates each tool invocation through sequential layers (first match wins):

1. **Hard Deny**: Immediately blocks recursive deletes outside workspace, credential reads (`~/.ssh`, `.env`, cloud tokens), git history rewrites (`push --force`, `rebase`), package publishing, system file writes (`/etc`, shell rc), and gate tampering.
2. **Fast Allow**: Immediately permits parsed read-only commands (`cat`, `grep`, `git status`) and workspace-confined writes without invoking an LLM.
3. **Classifier**: Ambiguous or grey-area commands fall through to an LLM classifier (a configured currently available provider model (verify pricing and private-context transmission), or a local `llama.cpp` / Ollama endpoint) that reviews the pending call against conversation context and fail-closes on timeout.
4. **Scoped Action Approval**: If a command is denied or needs human judgment, the engine issues a single-use 6-character action token bound strictly to `(tool, normalized_cmd, cwd)`. You approve it by replying `> agy-approve <token>` in chat. Conversational phrases like "yes" or "proceed" are ignored to prevent ambient authority leakage.

Before activation, test allowed and denied operations in disposable fixtures, including symlink/path escapes, shell expansions, network requests, missing hook, classifier timeout and token replay. A unit-test pass is not proof all host access is intercepted. Preserve a verified disable/rollback path. No model classifier is merge or policy authority.

## Examples

### Example 1: Approving a Blocked Command

When an unclassified command is blocked, `agy-auto` outputs a token:
```text
tool call denied by pre-tool hook: [agy-auto/classifier] needs human approval: pip install requests. Reply '> agy-approve a1b2c3' in chat to proceed.
```
To authorize this specific command for a single run, reply directly in the chat:
```text
> agy-approve a1b2c3
```

### Example 2: Configuring a Local Model Backend

To run `agy-auto` completely offline using llama.cpp or Ollama instead of cloud APIs, edit `~/.gemini/config/agy-auto/policy.toml`:
```toml
[classifier]
endpoint = 
