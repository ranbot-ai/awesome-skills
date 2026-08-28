---
name: babysit-pr
description: Babysit a pull request through its bot review rounds: verify, fix, reply, resolve. Use for any babysit or watch-the-PR ask. 
category: AI & Agents
source: antigravity
tags: [node, api, ai, agent, gpt, document, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/babysit-pr
---

# Babysit a PR

## When to Use

- A PR/MR has accumulated bot review threads that need verification, fixes, replies, and resolution.
- You want to drive a PR from 'just opened' to 'nothing left unanswered' across multiple review rounds.

Goal: carry a pull request (GitHub) or merge request (GitLab) from "just opened" to "nothing left
unanswered," without the human having to sit and refresh the page. "PR" below means either.

Review bots are diff-anchored samplers. Every push mints a fresh round, and a fix in one place can
light up commentary somewhere adjacent. Left alone, a PR accumulates half-answered threads that
nobody resolves, and the real bug in round three gets buried under nitpicks from rounds one and two.
Your job is to be the person who reads every finding, decides what is actually true, fixes what
blocks, and closes every loop in writing.

You know how to drive `gh` (GitHub), `glab` (GitLab), and git. What follows is only the judgment this
loop needs and the few API calls that are easy to get wrong. The harvest script picks the forge from
the cwd's git origin; everything it returns has the same shape on both, with a `capabilities` block
naming what that forge cannot tell you.

## The three rules that matter most

Verify before you believe. A bot's severity badge is a guess made without running anything. Treat
every finding, including the P1s, as a claim to check against the code. Bots are frequently right
(that is why this loop is worth running), and they are also confidently wrong often enough that
shipping their suggestions unexamined will introduce bugs. Read the actual code path before you
agree or disagree.

Every thread gets an answer. A finding you fixed, rejected, or deferred is only closed once you have
said so in that thread and resolved it. Silence reads as "ignored" to the next human who opens the
PR, and it is how a real bug gets lost.

Publish before you answer. A "fixed" reply is only true once the remote branch carries the fix.
Never post a confirmed reply, or resolve its thread, while the fix exists only locally. Rejections
need no push. Reply with evidence and resolve immediately.

## Harvest the round

Findings arrive on two different surfaces, and a round that reads only one silently misses half of
them. This is the single most common way a babysit loop goes wrong:

- Inline review threads. This is where debate-review and Codex post their findings (Codex attaches
  P1/P2-badged inline comments to an otherwise boilerplate review body; an empty-looking body proves
  nothing). Each thread carries a `thread_id` (to resolve) and a `reply_to` (to reply inside the
  thread). On GitHub these are GraphQL review threads; on GitLab they are discussions.
- Top-level review bodies. This is where Greptile summarizes, Codex sometimes posts a numbered list,
  and debate-review posts its round summary. These have no thread to resolve; answer them with one PR
  comment per round. On GitHub they are review objects; on GitLab they are plain notes.

The bundled script returns both in one call, already correlated (`<skill-dir>` is the folder that
holds this SKILL.md):

```bash
"<skill-dir>/scripts/threads.sh" <N> > /tmp/pr-<N>-round-<k>.json
```

Never trust a filtered count without its unfiltered twin. Before applying any jq filter to the
harvest, print the raw totals (`jq '{threads: (.threads|length), reviews: (.reviews|length)}'`) and
compare. A filter that eliminates 100% of items is presumed broken until the field names are
verified against the actual schema (`jq '.threads[0] | keys'`). jq selects on a misspelled field
fail silently-empty, and a "clean round" built on one is how a P1 gets a merge-gate mention posted
over it. That has happened. GitHub tooling fails by returning less data, not by erroring; pair this with the
pagination rule.

Never describe an object you did not fetch. If a query for a specific id returns empty, that is a
stop signal. Say "I can't see it" and fetch it another way (`gh api .../reviews/<id>`), never narrate
its presumed content. Related trap: every inline thread reply arrives wrapped in a zero-byte
`COMMENTED` review object, so a watcher's "new review" event may be just a reply wrapper, not a new
round. threads.sh's `.reviews` does not include these wrappers, so a review id from an event that is
missing from the harvest means "wrapper", not "gone".

Diff it against the previous round's file to see what is genuinely new. `outdated: true` on a thread
means the line moved underneath it. The finding may already be fixed, so check it against current
code before spending the round on it. A `comment_count` bump on a thread you already handled means a
bot followed up inside it.

Has this reviewer seen the current push? Only trust a field that names a sha. On GitHub each review
carries `commit_id`; compare it to `head`. For debate-review on either forge, the round body's
`debate_head` is the sha it reviewed. On GitLab other reviewers' notes carry no sha (`capabilities.
re
