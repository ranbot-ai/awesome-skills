---
name: claude-agents
description: 'Ask Claude', 'have Claude build or review this': drive Claude Code headless (claude -p) from another agent as a peer, builder or fresh reviewer. 
category: AI & Agents
source: antigravity
tags: [python, react, api, mcp, claude, ai, agent, workflow, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/claude-agents
---


# Claude agents — Claude Code headless as a partner

## Operational boundaries

Keep the scope, sandbox, credentials and approval settings supplied by the user or host. Obtain authorization before delegating, exposing project files to another provider, enabling connectors or hooks, using paid services or deploying. Use synthetic or redacted inputs for examples. Keep security reviews static and defensive, with findings and fixes grounded in source inspection.

## When to Use

'Ask Claude', 'have Claude build or review this': drive Claude Code headless (claude -p) from another agent as a peer, builder or fresh reviewer.


**Run headless Claude Code as a peer, builder or fresh reviewer.** Any agent can run `claude -p` for a full session: the repository's instructions, its tools and a conversation that can continue. It is a partner with the same standing as its caller. A peer argues a decision through, a builder takes a stage, and a reviewer has never seen the build. This skill covers briefs, modes and mechanics through `<skill dir>/scripts/claude_agent.py`.

## Peer discipline

**Bring Claude in early, brief the goal and argue decisions through.** Give it the facts, the draft, the uncertainty, binding constraints and proof. Leave the means to its judgement and challenge it over several turns. Bring the owner one result or a clear deadlock, question of intent or missing fact. Apply `delegation` § Peer discussion for examples and convergence.

**A delegated diff is unreviewed code, and the session that wrote it never clears it.** Read it, check the disk and rerun its tests yourself. Apply `release-gate` § Stage and phase close for the checks and fresh review before a deployment.

**Keep product decisions, operational changes and final judgement with you.** Decide what the product should do, accept or reject review findings, perform final verification and judge whether a stage is done. Keep operational changes, including development deploys, applied migrations, pushes, provider settings and secrets, plus production credentials. The builder runs development suites within the brief's boundaries, one runner per shared dataset. It makes each operational step one command and names it for you to run. Apply the `delegation` skill.

**Write the diff yourself when the brief would be nearly as long.** Judge delegation by size, not time.

## Peer, builder or reviewer

| Role | Mode | What it can do | Session |
|---|---|---|---|
| Peer — argue a framing, pressure-test a claim, a second opinion on a plan | `consult` (default) | Read, Grep, Glob and the read-only shell (`git log`, `git diff`, `git status`); every write is denied | continued turn after turn |
| Builder — a stage with a goal, its binding decisions and how to prove it | `build` | Edits, shell, tests; a classifier reviews each action (auto mode) | continued within the stage |
| Reviewer — fresh eyes on an artifact, a plan, a change | `review` | Read, Grep, Glob only; no settings, hooks, plugins, MCP, project instructions or memory | always new, never saved |

- **A review needs a fresh session.** Never resume or fork the building thread, or use its subagent. `--fork-session` copies the builder's beliefs with its transcript. `--mode review` always starts a fresh session and never saves it.
- **Route reviews of commits through the `independent-review` skill's wrapper.** Review mode has no shell and cannot read a git range. The wrapper's `--reviewer claude` uses this same fresh headless session for a change before a push or a release. It writes the range's log and diffs to a file the reviewer pages through, and fails short rounds loudly. It loops until nothing introduced is above Low and no High or Critical of any age is open. Don't give review mode git commands instead: `Bash(git diff:*)` also allows `git diff --output=<file>` to write.
- **When the caller is itself Claude, a headless Claude is the same model family.** A consult still buys fresh context and different reasoning, but blind spots are shared. For independent review, prefer another family. The `independent-review` wrapper defaults to a fresh Codex session. Without Codex it uses fresh headless Claude Code, then Grok. Choose `--reviewer grok` for another family (`grok-agents`).
- **In consult and build the delegate reads what you read.** It loads the repository's `CLAUDE.md`, or `AGENTS.md` when no `CLAUDE.md` exists, and the user's `~/.claude/CLAUDE.md`. The project's auto-memory, hooks and skills load too. This suits a builder but makes it dependent on those instructions, which review mode excludes.

## The opening brief

**Give the brief what the repository's instructions do not contain.** Consult and build read those instructions themselves. Supply the decision at hand, conversation so far, and what you have already tried and rejected.

**Name the binding-spec files in a review brief.** Review mode reads nothing on its own.

**Put long briefs in a file and read them from there.** The wrapper sends eve
