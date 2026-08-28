---
name: claude-delegate
description: Delegate coding tasks to a separate Claude Code CLI process or Claude session only when the user explicitly requests it, while the orchestrator retains review and landing responsibility. 
category: AI & Agents
source: antigravity
tags: [node, mcp, claude, ai, agent, template, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/claude-delegate
---

# Claude Delegate

## When to Use

- You want to delegate a bounded coding task to a separate `claude` implementer (`Claude Code`) and then review its diff yourself.
- The user explicitly asked for delegation to this implementer.

You are the **orchestrator**. Delegate one bounded coding task to a separate **implementer** — a Claude
Code CLI session — then review what it produced and land it yourself. You write the brief and own the
judgment; the separate Claude session edits the working tree; you verify and commit.

This skill is not a signal for the current Claude to implement directly. Use it only after the human
explicitly asks for delegation to another Claude Code process or session.

## When not to use this

- The human asked the current agent to implement the task directly.
- The task is small enough to do inline and the human did not request delegation.
- The `claude` CLI is missing or unauthenticated (`claude auth status`).
- The task needs a stronger host boundary than Claude Code's tool permissions and shell-only sandbox
  provide. Use an isolated container or VM for that requirement.

## Prerequisites

1. `claude --version` succeeds.
2. `claude auth status` reports an authenticated session. On macOS the live credentials sit in the
   login Keychain; when the orchestrator's own sandbox blocks Keychain access (Codex's sandbox
   does), `claude` falls back to a possibly stale credentials file and reports `loggedIn: false`
   even though the login is valid. Re-run the check — and the dispatch itself — with that sandbox
   escalated or outside it before concluding the CLI is unauthenticated.
3. The target repository is the directory passed with `--cd`.
4. On Linux/WSL2, Claude's sandbox dependencies are installed. The normal relay profile is
   configured to fail when the sandbox is unavailable instead of silently running shell commands
   unsandboxed. Existing merged settings can still affect the effective boundary.

## The loop

### 1. Write the brief

The separate session has no orchestrator chat history. It receives the brief on stdin and can inspect
the target working tree.

Claude Code automatically discovers the target project's `CLAUDE.md` and normal local Claude
configuration because the relay does not use `--bare`. It does **not** generically auto-load
`AGENTS.md`. Read `AGENTS.md` yourself and copy every load-bearing constraint and the real gate
commands into the brief. Tell the implementer not to commit. Keep one task per brief.

Template and details: [references/writing-the-brief.md](references/writing-the-brief.md).

### 2. Dispatch

```bash
node "<skill-dir>/scripts/relay.mjs" --brief brief.txt --cd /path/to/repo
# review/diagnosis only:                 add --read-only
# continue the latest session:           add --resume-last
# continue the recorded session:         add --session <id>
# choose limits:                         add --max-turns 40 --max-budget-usd 10
# hard relay deadline:                   add --timeout 2h
# inspect every option:                  node .../relay.mjs --help
```

`<skill-dir>` is this installed skill directory, the folder containing this `SKILL.md`.

The relay runs `claude -p --output-format stream-json --verbose`, sends the brief through stdin, and
writes artifacts under the system temp directory by default. It never uses `--bg` or `--bare`, and it
never commits. See [references/dispatch-and-poll.md](references/dispatch-and-poll.md).

### 3. Wait

The relay blocks until Claude exits. Use the orchestrator's background-command facility, or run it in
the foreground and wait. Completion means the process exited and `result.json` exists.

- A pre-run usage error exits 2 and writes no `result.json`.
- A missing `claude` exits 127 and writes `status: "claude_unavailable"`.
- Timeout and caught relay signals terminate the whole implementer process tree and preserve an
  outcome artifact.

Read `finalMessage`, `touchedFiles`, `resultSubtype`, and the raw artifact paths from `result.json`.

### 4. Review

Treat the implementer's report and gate outcomes as claims:

- Review edits to existing tests before a green gate means anything.
- Re-run the project's actual gates yourself.
- Read the complete diff against the brief, starting with `touchedFiles`.
- Inspect untracked and staged content as well as the ordinary diff.
- Run relevant guard skills if installed.

Full checklist: [references/review-and-land.md](references/review-and-land.md).

### 5. Land

The **orchestrator commits** only after the gates pass and the diff holds. For rework, resume the same
Claude session with a delta brief:

```bash
echo "Keep the implementation, replace the mocked DB test with the migrated fixture, and remove the
unused import." | node "<skill-dir>/scripts/relay.mjs" --session <id> --cd /path/to/repo
```

Review a resumed run exactly like the first run.

## Permission profiles

The normal profile is deliberately explicit:

- `acceptEdits` permission mode.
- Built-in tools restricted t
