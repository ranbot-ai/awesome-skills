---
name: aider-delegate
description: Delegate coding tasks to Aider (`aider`) only when the user explicitly requests it, while the orchestrator retains review and landing responsibility. 
category: Document Processing
source: antigravity
tags: [python, node, api, ai, agent, llm, design, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aider-delegate
---

# Aider Delegate

## When to Use

- You want to delegate a bounded coding task to a separate `aider` implementer (`Aider`) and then review its diff yourself.
- The user explicitly asked for delegation to this implementer.

You are the **orchestrator**. Hand a bounded coding task to a separate **implementer** - Aider - then
review what it produced and land it yourself. You write the brief and own the judgment; Aider does the
typing in its own run; you verify and commit.

The loop needs only a shell command and file access, so any comparable orchestrator can drive it.

## Runtime availability and authorization

This tracked bundle has documentation only: scripts/relay.mjs is absent. Do not run the documented path or automatically install it/Aider. Use an already reviewed installed runtime, or stop that execution path and prepare a separately authorized pinned installation. CLI flags/defaults and result semantics below describe an upstream version, not locally verified behavior. Review actual runtime/config/hooks before dispatch.

Delegation sends selected code, brief and repository context to the configured provider; confirm the intended endpoint/data policy and cost limit. Use a non-secret placeholder only for a trusted local endpoint that ignores credentials, never send a real provider key to an arbitrary api-base. Logs/history can retain private code and keys; protect paths and retention. Disable or review repository lint/test commands before execution. A dry run can still write history/cache and incur model costs. The orchestrator retains publication/commit authority from the actual task; this skill alone does not grant it.

## The one thing to know about Aider

**Aider commits by default.** Two of its defaults would destroy the reviewable diff this skill exists
to produce:

- `--auto-commits` (default `True`) - Aider commits its own edits after each exchange.
- `--dirty-commits` (default `True`) - Aider commits **your** pre-existing uncommitted work before it
  starts editing.

The relay always passes `--no-auto-commits` and `--no-dirty-commits`, and neither is configurable
through it. If you ever drive `aider` by hand instead of through the relay, pass both yourself, or the
work lands as commits you never reviewed. The relay also passes `--no-gitignore`, because Aider
otherwise writes `.aider*` into `.gitignore` on startup and dirties the tree you are about to read.

## When NOT to use this

- The task is small enough to do inline; delegation overhead is not worth it.
- The `aider` CLI is not installed, or no model is configured for it.
- You want the implementer to manage its own commits. Aider can, but this skill deliberately turns
  that off - the diff is the deliverable.

## Prerequisites (check once)

1. Install Aider - `python -m pip install aider-chat`, or the standalone installer from the
   [Aider install docs](https://aider.chat/docs/install.html).
2. Configure a model. Aider reads provider keys from the environment (`OPENAI_API_KEY`,
   `ANTHROPIC_API_KEY`, …) or its own config; see [Aider's model docs](https://aider.chat/docs/llms.html).
3. Confirm `aider --version` succeeds.
4. Work in, or point `--cd` at, the target git repository.

## Choose the model

Aider uses its own configured model when `--model` is omitted. Pass `--model <name>` to pick another.

## Local and self-hosted models

Aider talks to any OpenAI-compatible endpoint, so this is also the skill for delegating to a model
running on the user's own hardware - llama.cpp's server, Ollama, vLLM, LM Studio, or anything else
that serves the same API. Pair `--model` with `--api-base`:

```bash
node "<skill-dir>/scripts/relay.mjs" --brief brief.txt --cd /path/to/repo \
  --model openai/<served-model-name> --api-base http://127.0.0.1:<port>/v1
```

Three things differ from a hosted provider:

- **The `openai/` prefix is required.** It tells Aider to speak the OpenAI protocol to your endpoint;
  the part after it is whatever name your server reports, not a provider catalog name.
- **A placeholder key is still needed.** Export any non-empty `OPENAI_API_KEY`. The client library
  requires the header even when the server ignores its value.
- **Ask for a smaller edit format.** Local models often fail Aider's default `diff` format, which
  requires exact search/replace blocks. `--edit-format whole` trades tokens for reliability; keep the
  brief's scope tight with `--file` so whole-file rewrites stay cheap.

A local endpoint that is not running looks like a hang, not an error: Aider retries the connection
until the relay's `--timeout` watchdog fires and reports `status: "timeout"`. Confirm the server is up
before dispatching a long brief.

### Staying offline

The listed flags reduce known automatic requests; they do not prove offline operation. Model requests, repository config/lint/hooks and dependencies may still use the network. Enforce egress outside the child when offline behavior is required.

No account or provider registration is inv
