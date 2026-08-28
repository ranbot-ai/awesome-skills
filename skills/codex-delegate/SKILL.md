---
name: codex-delegate
description: Delegate coding tasks to the OpenAI Codex CLI only when the user explicitly requests it, while the orchestrator retains review and landing responsibility. 
category: Development & Code Tools
source: antigravity
tags: [node, claude, ai, agent, template, design, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/codex-delegate
---

# Codex Delegate

## When to Use

- You want to delegate a bounded coding task to a separate `codex` implementer (`OpenAI Codex`) and then review its diff yourself.
- The user explicitly asked for delegation to this implementer.

You are the **orchestrator**. This skill lets you hand a bounded coding task to a separate
**implementer** — the OpenAI Codex CLI — then review what it produced and land it yourself. You write
the brief and own the judgment; Codex does the typing in its own sandbox; you verify and commit.

Nothing here is specific to one orchestrating agent. The loop needs only the ability to run a shell
command and read a file, so it works the same whether you are Claude Code, OpenCode with a selected
model, or any comparable agent. (It is designed for and run on Claude Code; treat other orchestrators
as designed-for, not yet proven.)

## When NOT to use this

- The task is small enough to just do inline — delegation overhead is not worth it.
- The `codex` CLI is not installed or not authenticated (run `codex login`).
- You want to write the code yourself, or you only need a review (use Codex's own `review` command).

## Prerequisites (check once)

1. `codex --version` succeeds. If not, install (`npm i -g @openai/codex`) and `codex login`.
2. **Confirm which `codex` is on PATH.** Multiple installs are common (e.g. a current npm/nvm copy and
   a stale Homebrew one). `command -v codex` shows the active one and `codex --version` its version —
   an old binary predates flags this skill relies on (`codex exec --json`, `-o`, `exec resume`). The
   relay also records the version it ran into `result.json`, so a stale binary is visible after the fact.
3. You are in (or will point `--cd` at) the target git repository.

## The loop

Run these five steps per task. Steps 1, 4, and 5 are your judgment; 2 and 3 are mechanical.

### 1. Write the brief

Codex sees **only** the text you send — no repo memory, no chat history, no shared context. Everything the
task needs goes in the brief: the goal, the current state, what to change, what to leave untouched,
the project's **actual** gate commands (discover them from the repo's CLAUDE.md/AGENTS.md/Makefile —
do not assume), and a report contract. Tell Codex it will **not** commit (you will). Keep one task per
brief. Full guidance and a template: [references/writing-the-brief.md](references/writing-the-brief.md).

### 2. Dispatch

Send the brief to Codex with the bundled helper. It wraps `codex exec`, captures the run, and writes a
structured `result.json` — so your only job is "run a command, read a file." (`<skill-dir>` below is
this skill's installed directory — the folder containing this `SKILL.md`, i.e. the directory you loaded
the skill from. Claude Code prints it as "Base directory for this skill" when the skill loads; on other
orchestrators use that same directory — if unsure where it landed, run
`find ~ -name relay.mjs -path '*codex-delegate*'` and substitute the directory above it.)

```bash
node "<skill-dir>/scripts/relay.mjs" --brief brief.txt --cd /path/to/repo
# read-only (review/diagnosis, no edits):   add --read-only
# continue the exact Codex session:         add --session <threadId>  (from result.json; send only the delta brief)
# fallback when no thread id is available:  add --resume-last
# hard time limit (watchdog):               add --timeout 2h  (default: off; implementation runs routinely need 1-2h)
# see all options:                          node .../relay.mjs --help
```

The helper defaults to a write-capable (`workspace-write`) sandbox and writes its artifacts to a temp
dir, so the repo under review stays clean. It **never commits** — see step 5. Mechanics, flags, and the
`result.json` shape: [references/dispatch-and-poll.md](references/dispatch-and-poll.md).

### 3. Wait for completion

The helper blocks until Codex finishes, so back it with whatever your orchestrator offers and resume
when it returns:

- **Claude Code:** run the Bash call with `run_in_background: true`; you are notified on completion.
- **Plain shell / other agents:** run it in the foreground for short tasks, or background it and poll
  the result file — `… &` in bash/zsh (including Git Bash/WSL), or your shell's equivalent (`Start-Job`
  in PowerShell, `start /b` in cmd). The run is done when `result.json` exists with a `status`. (A
  pre-run usage error — bad args or an empty brief — instead exits with code 2 and a stderr message and
  writes no result file, so check the exit code too. A missing `codex` binary exits 127 but *does* write
  a `result.json` with status `codex_unavailable`.)

Do not trust progress trackers over reality: a run is finished when `result.json` is written and the
process has exited. Read the working tree, not a status line. The implementer's full report is
the `finalMessage` field in `result.json` (also printed in full on stdout between the report markers).

### 4. Review — do not trust the self-report

Codex's `result.json` includes its own sum
