---
name: agy-delegate
description: Delegate coding tasks to the Google Antigravity CLI (`agy`) only when the user explicitly requests it, while the orchestrator retains review and landing responsibility. 
category: Document Processing
source: antigravity
tags: [node, claude, ai, agent, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agy-delegate
---

# Antigravity Delegate

## When to Use

- You want to delegate a bounded coding task to a separate `agy` implementer (`Google Antigravity`) and then review its diff yourself.
- The user explicitly asked for delegation to this implementer.

You are the **orchestrator**. This skill lets you hand a bounded coding task to a separate
**implementer** - the Google Antigravity CLI (`agy`) - then review what it produced and land it
yourself. You write the brief and own the judgment; Antigravity does the typing in its own
conversation; you verify and commit.

Nothing here is specific to one orchestrating agent. The loop needs only the ability to run a shell
command and read a file, so any comparable agent can drive it. It is designed for and run on Claude
Code; treat other orchestrators as designed-for, not yet proven.

## When NOT to use this

- The task is small enough to just do inline - delegation overhead is not worth it.
- The `agy` CLI is not installed or not authenticated. Install it from Antigravity's CLI docs and run
  the first-launch setup.
- You want to write the code yourself, or you only need Antigravity's opinion on code you wrote (a
  `--read-only` dispatch covers review without edits, but a plain review may not need delegation at all).

## Runtime availability

This is a docs-only import: `scripts/relay.mjs` is absent. Do not run the dispatch commands from this directory or invent its output. Obtain a separately authorized upstream checkout and inspect runtime, dependencies and license first. The flags/result schema below describe the imported upstream contract, not tested functionality in this bundle.

## Prerequisites (check once)

1. `agy help` succeeds. If not, install the Antigravity CLI and complete first-launch setup.
2. `agy models` succeeds. That proves the CLI can authenticate and list the available model labels.
3. You are in (or will point `--cd` at) the target git repository.

These checks do not prove that a headless write will be approved. In `--print` mode, Antigravity
cannot prompt for a write permission and may auto-deny it. The relay detects that denial instead of
reporting completion.

## Choose the implementer model

`agy` has a configured default model, so `--model` is optional. Use it when the human has a preferred
Antigravity model label for the task. Otherwise let Antigravity use its own current default rather than
guessing.

## The loop

Run these five steps per task. Steps 1, 4, and 5 are your judgment; 2 and 3 are mechanical.

### 1. Write the brief

Antigravity sees only the text you send plus what it can inspect in the workspace - no chat history, no
shared context. Everything the task needs goes in the brief: the goal, the current state, what to
change, what to leave untouched, the project's **actual** gate commands, and a report contract. Tell
Antigravity it will **not** commit (you will). Keep one task per brief. Full guidance and a template:
[references/writing-the-brief.md](references/writing-the-brief.md).

### 2. Dispatch

Send the brief to Antigravity with a separately obtained, reviewed upstream helper. It wraps `agy --print`, captures the run, and
writes a structured `result.json` - so your only job is "run a command, read a file." (`<skill-dir>`
below means the reviewed upstream runtime directory; this installed catalog directory has no executable helper.)

```bash
node "<skill-dir>/scripts/relay.mjs" --brief brief.txt --cd /path/to/repo
# choose a model label:                 add --model "<label from agy models>"
# reasoning effort (low, medium, high): add --effort high
# read-only (plan mode — no edits):     add --read-only
# enable Antigravity terminal sandbox:  add --sandbox
# resume the most recent conversation:  add --resume-last  (delta brief only)
# see all options:                      node .../relay.mjs --help
```

The helper starts a fresh Antigravity project by default and passes `--add-dir <repo>` (the `--cd`
path, absolute) so `agy` has an explicit workspace. It does **not** pass `--dangerously-skip-permissions` by default.
Mechanics, flags, and the `result.json` shape: [references/dispatch-and-poll.md](references/dispatch-and-poll.md).

### 3. Wait for completion

The helper blocks until Antigravity finishes, so back it with whatever your orchestrator offers and
resume when it returns:

- **Claude Code:** run the Bash call with `run_in_background: true`; you are notified on completion.
- **Plain shell / other agents:** run it in the foreground for short tasks, or background it and poll
  the result file.

Do not trust progress trackers over reality: a run is finished when `result.json` is written and the
process has exited. Read the working tree, not a status line. The implementer's full report is
the `finalMessage` field in `result.json` (also printed in full on stdout between the report markers).

### 4. Review - do not trust the self-report

Antigravity's `result.json` includes its own final message and any gate claims. **Re-verify, don't
ac
