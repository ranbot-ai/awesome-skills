---
name: agent-memory-discipline
description: Rules for when an agent should recall from long-term memory before acting and when it should save decisions, corrections and failures afterwards. Works with any memory backend. 
category: AI & Agents
source: antigravity
tags: [markdown, api, mcp, claude, ai, agent, design, document, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-memory-discipline
---


# Agent Memory Discipline

## Overview

Connecting a memory tool does not make an agent use it: tools register, the session runs, and nothing gets recalled or saved. This skill supplies the missing part, standing rules for when to read memory and when to write it.

The problem it solves is specific. An agent with memory available still repeats settled questions, reverts corrected habits, and loses decisions between sessions, because nothing tells it when recall and save are due. The rules below make both moments explicit.

## When to Use This Skill

- Use when a memory tool or MCP memory server is connected but the agent is not using it consistently.
- Use when the user complains that the assistant loses preferences, conventions or past decisions between sessions.
- Use when setting up persistent memory for a project and the agent needs standing rules for reading and writing it.
- Use when the user says "remember this", "what did we decide", "recall", or "save this for next time".

## How It Works

### Before You Start: Any Memory Backend

The agent needs a memory tool it can call. Any backend works, and the rules are identical for each:

- **Files.** A `memory/` folder of Markdown notes, one fact per file. No dependencies, fully greppable, versionable in git.
- **A local MCP memory server.** Keeps everything on the local machine; several open-source options exist.
- **A hosted memory service over MCP.** Adds portability across tools and machines at the cost of the data living elsewhere.

Authentication is whatever the chosen backend requires: none for a local folder, the server's own configuration for a local MCP server, an API key or OAuth sign-in for a hosted service. This skill never handles credentials itself and never writes them into memory.

### Step 1: Recall Before Acting

Read memory **before** doing any of these, not after:

- starting work on a project touched before
- choosing a library, pattern, or tool
- writing tests, commits, or documentation, where conventions apply
- answering "how do we usually do X here"
- anything the user phrases as "again", "like last time", or "as we agreed"

Skip recall for one-off factual questions, arithmetic, or anything fully specified in the current message. Recall costs a tool call and context; spending it on a self-contained question is waste.

Search with the words the user actually used, plus the project or repository name. If the first search returns nothing useful, try one broader query, then stop and proceed without memory rather than looping.

### Step 2: Save After Deciding

Write to memory when one of these has just happened:

- a **decision** was made and will still matter next week ("we use pnpm", "the billing module stays untouched")
- the user **corrected** the agent, which is the strongest signal there is
- an approach **failed**, and why it failed
- a preference was stated that applies beyond this task
- a fact about the environment was discovered the hard way (a port, a flag, a service that must be running)

Do **not** save: the contents of files that can be read again, restatements of the current task, transient state, anything the user marked as temporary, and anything containing secrets, tokens, or personal data.

One memory, one fact. A paragraph containing four decisions cannot be superseded cleanly when one of them changes.

### Step 3: Write It So It Survives

A memory that is useless in three weeks was written wrong. Give each entry, in the text if the backend has no fields for it:

- **what** was decided or observed, in one sentence
- **why**, briefly, because the reason outlives the decision
- **when** it became true, and when it stopped being true if it has
- **where it came from**: a file, a commit, a conversation, a test run

Prefer the user's own words over a paraphrase. Paraphrase drifts.

### Step 4: Close the Past Instead of Overwriting It

When something changes, the old memory is not wrong. It is **closed**.

If the project moved from Redux to Zustand, "we use Redux" was true from January to June. Deleting it destroys the explanation for every component written in that window. Mark it superseded, keep its validity window, and write the new one alongside.

This is the single most destructive habit in agent memory, and it stays invisible until someone asks a question about old code.

### Step 5: Keep Contradictions Visible

If recall returns two entries that disagree, do not pick the closer match and proceed. Surface both, with their dates, and ask or flag. A convention that a recent failure contradicts is exactly the situation where the user needs to be told, not smoothed over.

### Step 6: Weigh Evidence and Policy Differently

- **Evidence** is what happened: one run, one failure, one observation. Cheap, plentiful, individually unreliable.
- **Policy** is what should happen: a convention, a decision, a rule. Expensive, and should be hard to change by accident.

An observation becomes policy when a human confirms it, when 
