---
name: delegate-setup
description: Configure approved delegation lanes across installed implementer CLIs, including optional model and effort choices, then write global or project config only after explicit user approval. 
category: AI & Agents
source: antigravity
tags: [node, claude, ai, agent, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/delegate-setup
---

# Delegate Setup

## When to Use

- You want to configure which implementer CLI handles which kind of work (fleet lanes).
- You need to discover installed implementers and write lane config after user approval.

You are the **orchestrator** in **setup mode**. Discover installed implementer CLIs, propose a
**fleet of lanes**, and write configuration only after the user approves.

This skill does **not** dispatch coding work. It only authors the lane map.

One concept: **lanes**. Never say “routes.”

Example lane: **feature** → implementer `opencode`, model `opencode/grok`, variant `high`
(OpenCode uses `variant` for reasoning intensity, not `effort`).

## When NOT to use this

- The user wants a task implemented — use the matching `*-delegate` skill instead.
- A one-off model change on a single dispatch — pass `--model` / `--effort` / `--variant` on that relay.

## Hard rules

1. Every lane **must** include `implementer`.
2. Put dials on the same object (`model`, `effort` or `variant`, …) only if that implementer supports them — see [references/schema.md](references/schema.md).
3. Show a human-readable lane table **and** the full JSON before every write; re-show after every tweak.
4. Write **only** after an explicit approval (“yes”, “approve”, “write it”).
5. Ask scope unless already clear: **global** (all projects) vs **this repo only**. Never create a project file just because cwd is a git repo. If there is no git repo, default to global and say so.
6. Do not invent model identifiers.
7. In interview or usage-scan mode, never write **any** dial the user did not give you and the schema does not require — omit it, so the CLI’s or relay’s own default applies.
8. Prefer 3–5 useful lanes over a kitchen-sink map.
9. Never edit `AGENTS.md`, `CLAUDE.md`, or other user agent-instruction files.
10. Never run a `*-delegate` relay from this skill.

(`<skill-dir>` is this skill’s install directory — the folder that contains this `SKILL.md`.)

## Flow

`discover → load → grounding menu → propose (with Basis) → scope → approve → write`

### 1. Discover

```bash
node "<skill-dir>/scripts/discover.mjs"
```

Summarize installed vs missing, auth (`true` / `false` / `null` = unknown), and whether models were
`reported`, `aliases` (curated aliases in the registry, not live discovery — full model names also
work), `unsupported`, or `failed`.

### 2. Load existing (effective map)

```bash
node "<skill-dir>/scripts/config.mjs" load --cwd "$PWD"
```

- Neither present → “No lanes configured yet.”
- Otherwise → table of **effective** lanes with a Source column (`global` / `project`). Do not paste
  both raw files unless asked.
- If `projectPresent` is true and `projectTrusted` is false, label the project lanes **untrusted**.
  They cannot dispatch until the user reviews and approves a project write.

### 3. Propose

Discovery reports capability, never task fit. So ask **one** grounding question before proposing
anything — one question, three options, not a wizard:

> How should I pick the lanes? **(1) Quick defaults** — I decide, no questions.
> **(2) Interview** — about four questions on how you want work allocated.
> **(3) Usage scan** — I re-read your CLIs’ local session folders (counts and dates only, never the
> conversations) and let the numbers place your lanes — if one CLI dominates, expect one question
> about its role. Happy to do 2 and 3 together.

- **Quick defaults** → propose immediately.
- **Interview** → the four questions (allocation policy, never model rankings) and how to ask them
  (one medium per round) live in [references/setup-dialogue.md](references/setup-dialogue.md) — read
  it before you ask.
- **Usage scan** → `node "<skill-dir>/scripts/discover.mjs" --usage`. Tell the user it is metadata
  only before running it. Each discovered CLI gains `usage: { sessions, lastUsed }`; `null` means no
  probe is wired — unknown, not unused.
- **Both** → run the scan first, then ask only what the numbers cannot answer.
- Inside a git repo, repo signals (languages, test weight, frontend share) are a fourth source of
  evidence. They do not change the menu; they feed the proposal and the `repo` basis.

**That menu is also the consent surface** — the option chosen sets how much of the map is yours to
decide:

- **Quick defaults** — the user hired your opinion. A full map is legitimate, dials included; label
  every lane `my opinion`, say plainly that the map is your opinion, and keep it cheap to revise.
- **Interview / usage scan** — evidence modes, so **every** dial is gated (rule 7): set one only from
  the user’s answer, or where the schema requires it (opencode lanes require `model`). Omitting is
  always safe — every dial has a default the user already lives with, and a CLI’s configured default
  is their standing choice, better evidence than your priors. Choosing which installed implementer
  gets a lane is still yours — Basis `my opinion` — but a dial that raises spend is not: offer your
  dial picks only as an add
