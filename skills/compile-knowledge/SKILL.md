---
name: compile-knowledge
description: Compile durable, non-obvious findings into an interlinked markdown knowledge store — atomic files, [[wiki-links]], a maintained index — so an agent gets smarter across sessions instead of relearni
category: Document Processing
source: antigravity
tags: [markdown, api, claude, ai, agent, document, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/compile-knowledge
---


# Compile Knowledge

## Overview

Durable knowledge is worth keeping as many small, interlinked markdown files compiled over
time and surfaced through an index — not as one giant doc, a chat log, or a one-off
`notes.md` that rots. This skill makes compiling consistent, so what an agent learns in one
session is retrievable in the next one instead of being re-derived from scratch.

The shape is deliberately boring: one fact per file, a one-line `description` that recall
matches against, `[[slug]]` links between related files, and a single index line per entry.
The hard part is not the format — it is the discipline of writing only what is durable, and
of updating an existing file instead of creating a near-duplicate.

## When to Use This Skill

- Use when you have just produced research, competitive intel, a digest, or an
  investigation result, and are about to close the task — compile before you close.
- Use when you learn a non-obvious fact the hard way (a tool that fails silently, a
  measurement that contradicts the docs, a constraint nobody wrote down).
- Use when the user says "save this", "write this to the wiki", "update the memory",
  "log this finding", "structure this knowledge", or "follow the karpathy method".
- Do **not** use it for routine work. A deploy, a restart, or a one-line fix usually
  produces nothing durable, and filler pollutes recall.

## How It Works

### Step 1: Pick the store

- **Agent memory** — the per-agent folder your harness already loads (`memory/` with an
  index file such as `MEMORY.md`). This is the default and, for a solo agent, usually the
  only store you need.
- **Shared wiki** — a `wiki/` folder with `wiki/index.md`, for knowledge the whole team
  would otherwise re-derive. Skip it entirely if you work alone; do not manufacture team
  ceremony.

Rule of thumb: "only I act on this" goes to memory, "anyone on my team might need this"
goes to the wiki. Cross-link the two with `[[slug]]` rather than copying the fact into both.

### Step 2: Pass the hygiene gate

Compile only a fact that is **durable** and **non-obvious**. Skip it if it is derivable from
the repository, the git history, or the existing docs; if it is true only for this one
conversation; or if an existing file already covers it — in that last case update that file.

### Step 3: Search before you write

Grep the store and skim the index for the topic. A near-duplicate is worse than no entry,
because recall then has two answers and no way to choose between them.

### Step 4: Write one atomic file

One fact per file. Two unrelated facts are two files. Name it as a kebab-case slug — the
slug is the link target, so it has to be guessable by the next reader. Frontmatter carries
`name` (equal to the slug), a one-line `description` specific enough to be matched during
recall, and a type or category. In the body, state the fact plainly and link related
entries with `[[slug]]` liberally; a link to a file that does not exist yet is a fine TODO
marker, not an error.

### Step 5: Add exactly one index line

Use one line in the form `- Title → slug.md — hook`, under ~200 characters. Detail lives in
the file; an index line that restates the file defeats the point of having an index. Create
the index if it is missing, or the store is undiscoverable.

### Step 6: Age the fact instead of letting it rot

Facts expire. When one is time-sensitive or replaces an older one, say so in the
frontmatter so recall can demote it rather than serving stale truth:

- `valid_to: YYYY-MM-DD` — the date the fact needs a recheck.
- `supersedes: <slug>` — the older fact this replaces. Prefer this over editing in place
  when the old value is still worth seeing; edit in place when it is not.
- `confidence: high|medium|low` — so a hunch never outranks a measurement.
- `provenance: "<source>"` — where the fact came from, distinct from who wrote the note.

All four are optional and portable; omitting them changes nothing.

## Examples

### Example 1: A measured, non-obvious fact goes to memory

```markdown
---
name: reference_search_api_counts_prs_as_issues
description: "GitHub's /search/issues endpoint counts pull requests in total_count, so a zero there proves neither issues nor PRs exist — but a non-zero one does not tell you which."
confidence: high
provenance: "measured 2026-08-16 while dupe-checking four upstream repos"
---

`total_count` from `/search/issues?q=<term>+repo:<owner>/<name>` is the sum of issues and
pull requests. For a "has anyone submitted this yet?" check that is exactly what you want,
and the zero is a real absence. To separate the two, add `type:pr` or `type:issue`.

Related: [[reference_gh_api_ref_serves_default_branch]].
```

Then one line in the index:

```markdown
- Search API counts PRs as issues → reference_search_api_counts_prs_as_issues.md — a zero is a real absence, a non-zero is ambiguous
```

### Example 2: Nothing durable came out of the task

```
Task: bump the service's log level to debug and restart it.
