---
name: codex-agents
description: 'Ask Codex', 'check with Codex', handing Codex a build or review, or stuck between two framings: the Codex CLI as peer, builder or fresh reviewer. 
category: AI & Agents
source: antigravity
tags: [python, react, api, claude, ai, agent, gpt, workflow, design, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/codex-agents
---


# Codex agents — the Codex CLI as peer, builder and reviewer

## Operational boundaries

Keep the scope, sandbox, credentials and approval settings supplied by the user or host. Obtain authorization before delegating, exposing project files to another provider, enabling connectors or hooks, using paid services or deploying. Use synthetic or redacted inputs for examples. Keep security reviews static and defensive, with findings and fixes grounded in source inspection.

## When to Use

'Ask Codex', 'check with Codex', handing Codex a build or review, or stuck between two framings: the Codex CLI as peer, builder or fresh reviewer.


**Treat Codex as a peer with the same standing as Claude.** Not a formatter, not a gate, not an authority.

**Confirm the build model and the review model with the user.** They are two choices. For each, suggest the newest GPT Sol their Codex lists, at `high` or `xhigh` (`--effort`; the wrapper's default is `xhigh`). The list is `models[].slug` in `~/.codex/models_cache.json` (verified `2026-11-18`, Codex CLI 0.169.0); without it, ask. A standing preference goes into the user's own `CLAUDE.md` or `AGENTS.md`, never a skill or the wrapper's state, so later sessions read it there and don't ask again. The author's example, chosen `2026-11-18`: GPT-6.2 Sol at `xhigh` for both.

**It can build, and what it builds is reviewed by someone else.** Hand it a build stage with the goal, binding decisions and files it will touch. Read its diff before believing it; a delegated diff is unreviewed code. The session that wrote code never clears it. An independent review does, through `independent-review` or whatever the project uses. Codex can review code it didn't write (§ Reviewer).

**Keep product decisions, operational changes and stage-completion judgement with the session agent.** This includes accepting or rejecting review findings, deploys, applied migrations, pushes, provider settings, secrets and production credentials. Development tests are builder work: run them, fix failures and report their results. Serialize suites on shared development data. Hand new migrations to the session agent to apply before dependent tests; name each operational step as one command for it. Without a runnable Codex CLI, or while it is out of usage (§ Resume or start fresh), the session agent builds the stage itself.

**Delegate only what is worth the hand-off; the test is size, not time.** If the brief would be nearly as long as the diff, write the diff. A stage small enough to describe precisely is small enough to write, and handing it over only buys a wait. Stop a build round that has made no writes on a small change; twelve minutes on a fifteen-line change is enough. Check `git status`. Kill its leftover process and write the change in-session. The session agent keeps the same responsibilities, and its diff still gets independent review.

**Bring Codex in while the framing is still open.** Invoke it for "check with Codex", "iterate with Codex", "ideate with Codex" and similar requests. Reach for it yourself when a load-bearing decision needs a peer or when different model blind spots matter. Keep routine drafting, formatting and mechanical tasks in-session.

**Give Codex the goal, the facts and the decision you need to make.** Share the actual draft, alternatives and reasoning, and prescribe only binding constraints. Treat Codex's judgement as a peer's. Argue through critiques and options over several turns, then bring the human one result or a clear deadlock, question of intent or missing fact. Apply `delegation` § Peer discussion for examples and convergence.

**Ask for the deliverable's actual format, including an image when needed.** Codex can write code and generate images directly through multimodal output. If the goal is a PNG, say that. Don't translate it to "an HTML file we'll screenshot."

## Dispatch

**Keep resumable briefs in a persistent file and use `--read`.** Use the repository or a working folder outside session scratchpads and system temp. Apply `flight-deck` when the work must survive a restart.

```bash
python <skill dir>/scripts/codex.py --new --read <brief_file>
```

**Explicitly open required instruction sections beyond the entry-file context budget.** Codex can truncate long `AGENTS.md` files. Name needed sections in the brief and require opening them from disk; apply `agent-instructions` for the budget. On Windows, Codex CLI 0.169.0 reported a 32,768-byte budget; a 104,297-byte file lost its role table (observed `2026-11-16`).

Use the host-approved sandbox. Prefer read-only for review and workspace-write for authorized edits and tests. If a test cannot run within the boundary, hand it back with the exact reason.


**Leave builds uncommitted when the session agent owns the commit.** Ask for a commit-message handoff. On Codex CLI 0.159, Windows 11, `workspace-write` could neither commit nor run git in another checkout (observed 2026-10-25). All three restrictions below were reprodu
