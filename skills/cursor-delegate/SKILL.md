---
name: cursor-delegate
description: Delegate coding tasks to the Cursor Agent CLI (`cursor-agent`) only when the user explicitly requests it, while the orchestrator retains review and landing responsibility. 
category: AI & Agents
source: antigravity
tags: [node, claude, ai, agent, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cursor-delegate
---

# Cursor Delegate

## When to Use

- You want to delegate a bounded coding task to a separate `cursor` implementer (`Cursor Agent`) and then review its diff yourself.
- The user explicitly asked for delegation to this implementer.

You are the **orchestrator**. Hand a bounded coding task to a separate **implementer** — the Cursor
Agent CLI — then review what it produced and land it yourself. You write the brief and own the
judgment; Cursor does the typing in its own session; you verify and commit.

The loop needs only a shell command and file access, so any comparable orchestrator can drive it.

## When NOT to use this

- The task is small enough to do inline; delegation overhead is not worth it.
- The `cursor-agent` CLI is not installed or authenticated (run `cursor-agent login`).
- You want to write the code yourself, or you only need Cursor's opinion on code you wrote (a
  `--read-only` dispatch covers that — see below — but a plain review may not need delegation at all).

## Runtime availability

This docs-only bundle does not include `scripts/relay.mjs`. The commands below cannot run from this installed directory. Obtain and review an explicitly authorized upstream runtime separately, including its license and permission behavior; do not invent a replacement or automatically install it. In examples, `<skill-dir>` means that reviewed runtime directory.

## Prerequisites (check once)

1. `cursor-agent --version` succeeds. If not, follow the installer for your platform at
   [cursor.com/cli](https://cursor.com/cli), inspect what it will run, and authenticate with
   `cursor-agent login`.
2. `cursor-agent status` shows you logged in.
3. You are in (or will point `--cd` at) the target git repository. The relay passes `--trust`, so
   point it only at repositories you trust.

## Choose the model

Omitting `--model` uses your Cursor default (usually `auto` — Cursor picks). To pin one, pass
`--model <name>` with a name from the account's live `cursor-agent models` output — select from that
list rather than inventing a name. Parameterized forms like `<name>[context=1m,effort=high]` are
forwarded as-is. The model that actually served the run is recorded as `resolvedModel` in
`result.json`.

## The loop

Run these five steps per task. Steps 1, 4, and 5 require judgment; 2 and 3 are mechanical.

### 1. Write the brief

Cursor sees only the text you send plus what it can inspect in the workspace — no chat history or
shared context. Include the goal, current state, what to change, what to leave untouched, the
project's **actual** gates, and a report contract. Tell Cursor not to commit. Keep one task per
brief. See [references/writing-the-brief.md](references/writing-the-brief.md).

### 2. Dispatch

Confirm that the user authorized the selected approval mode, external provider/data sharing and writable scope. Default `--force` is broad automatic command approval; prefer `--no-force` unless that scope is authorized. Treat approval refusals as boundaries, not reasons to disable hooks or sandboxing. Logs and briefs may contain source code or secrets; restrict their permissions and retention.

Use a separately obtained and reviewed upstream helper; no executable helper is bundled here. It wraps `cursor-agent -p`, feeds the brief on stdin, captures the
structured event stream, and writes `result.json`. (`<skill-dir>` must be the reviewed upstream runtime folder, not this docs-only catalog directory.)

```bash
node "<skill-dir>/scripts/relay.mjs" --brief brief.txt --cd /path/to/repo
# read-only (plan mode — review/diagnosis, no edits):  add --read-only
# write-capable without automatic command approval:   add --no-force
# explicitly override Cursor's sandbox for this run:  add --sandbox enabled|disabled
# pin a model from `cursor-agent models`:              add --model <name>
# resume the most recent session:                      add --resume-last  (delta brief only)
# resume a specific session:                           add --session <id> (delta brief only)
# hard time limit (watchdog):                          add --timeout 2h  (the 30m default suits short runs; implementation briefs routinely need 1-2h)
# see all options:                                     node .../relay.mjs --help
```

The child process's cwd pins the workspace. On Cursor `2026.07.23` or newer, use repeatable
`--add-dir` flags only for extra workspace directories. The relay writes artifacts under the system
temp dir by default and never commits. See
[references/dispatch-and-poll.md](references/dispatch-and-poll.md).

### 3. Wait for completion

The helper blocks until Cursor finishes. Run it with the orchestrator's background-command facility,
or background it in the shell and poll for `result.json`. A pre-run usage error exits 2 and writes no
result; a missing `cursor-agent` exits 127 and writes `status: "cursor_agent_unavailable"`.

Trust process state and the working tree over a progress display. Completion means the process exited
and `result.json
