---
name: commandcode-delegate
description: Delegate coding tasks to the Command Code CLI (`cmd`) only when the user explicitly requests it, while the orchestrator retains review and landing responsibility. 
category: Document Processing
source: antigravity
tags: [node, claude, ai, agent, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/commandcode-delegate
---

# Command Code Delegate

## Runtime availability

This catalog tree contains documentation only. `scripts/relay.mjs` is absent; the relay commands and result fields below describe an external upstream installation, not bundled functionality. Before dispatch, locate a user-approved upstream revision, inspect the exact relay source, license and CLI help, and verify compatibility. Do not execute the absent path, fabricate the helper or claim its tests/results. Brief drafting and independent diff review can proceed without it. Compatibility metadata requires Node 22+; the older Node 18 statement below is superseded.

Delegation may send workspace content to the configured provider and incur charges. Use approved data and minimal credentials, private artifacts and finite time/turn budgets. A worktree does not isolate host files. Existing user authorization applies; ask only for genuinely unapproved host access or expanded scope.

## When to Use

- You want to delegate a bounded coding task to a separate `commandcode` implementer (`Command Code`) and then review its diff yourself.
- The user explicitly asked for delegation to this implementer.

You are the **orchestrator**. This skill lets you hand a bounded coding task to a separate
**implementer** — the Command Code CLI (`cmd`) — then review what it produced and land it yourself.
You write the brief and own the judgment; Command Code does the typing in your working tree; you
verify and commit.

Nothing here is specific to one orchestrating agent. The loop needs only the ability to run a shell
command and read a file, so it works the same whether you are Claude Code, OpenCode with a selected
model, or any comparable agent. (It is designed for and run on Claude Code; treat other orchestrators
as designed-for, not yet proven.)

## When NOT to use this

- The task is small enough to just do inline — delegation overhead is not worth it.
- The `cmd` CLI is not installed or not authenticated (run `cmd login`).
- You want to write the code yourself, or you only need a review (Command Code has its own `/review`).
- You are on native Windows and `cmdc --version` does not work. Upstream recommends WSL for stable Windows use.

## Read this before the first dispatch: the autonomy model

Command Code's headless mode has **exactly two states, with nothing in between**:

- **Default (`-p` with no `--yolo`):** read, grep, and glob work. Every write, edit, and shell call is
  refused by the CLI's permission layer, and headless mode has no prompt to grant them mid-run. This
  is the relay's `--read-only`.
- **`--yolo` (alias `--dangerously-skip-permissions`):** every tool is allowed, anywhere the process
  can reach. There is no filesystem sandbox and no path restriction. This is what an implementation
  run needs, so the relay passes it by default.

`--permission-mode auto-accept` and `--tools-all` do **not** lift the headless write gate. Direct CLI
probes refused write, edit, and shell with both. So an implementation run
through Command Code is a full-trust run: scope it with a tight brief and a clean working tree, not
with a sandbox. The brief is guidance, and a git worktree isolates a checkout without containing the
process. If writes outside the target tree are unacceptable, use an OS-enforced sandbox such as
`codex-delegate` or run this one inside a container.

Before a write-capable run, verify whether the user has authorized this unsandboxed mode. Explain the scope and request acceptance only if that authority is absent; do not repeat a previously satisfied confirmation.

## Prerequisites (check once)

1. `cmd --version` succeeds and `cmd status` reports authenticated. If not, install Command Code and
   run `cmd login`.
2. **Confirm the CLI on PATH.** On macOS/Linux, `command -v cmd` shows the active `cmd`. On native
   Windows, use `cmdc --version`; `cmd` is the system shell. The relay uses `cmdc` there and launches
   its npm `.cmd` shim through `cmd.exe`. `COMMANDCODE_BIN` remains an absolute-path override and must
   never point to the system command interpreter. The relay records the version it ran in
   `result.json`, so a wrong binary is visible after the fact.
3. You are in (or will point `--cd` at) the target git repository, and its tree is clean before you
   dispatch — a full-trust run is much easier to review against a clean baseline.

## The loop

Run these five steps per task. Steps 1, 4, and 5 are your judgment; 2 and 3 are mechanical.

### 1. Write the brief

Command Code sees **only** the text you send — no repo memory, no chat history, no shared context
(beyond the repo's own `AGENTS.md`, which it reads automatically). Everything the task needs goes in
the brief: the goal, the current state, what to change, what to leave untouched, the project's
**actual** gate commands (discover them from the repo's AGENTS.md/CLAUDE.md/Makefile — do not assume),
and a report contract. Tell it that it will **not** commit (you will). Keep one task per brief. Full
guidanc
