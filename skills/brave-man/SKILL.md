---
name: brave-man
description: Runs a structured clarifying interview for new project requests before building. Instead of writing code, it outputs a fully specified prompt.md for a fresh agent session to execute, preventing expens
category: AI & Agents
source: antigravity
tags: [react, markdown, api, ai, agent, firebase, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/brave-man
---


# Brave Man

## Overview

Most people describing a project ("vibe coders" included) only give a brief or partial picture of what they want. They can't be expected to specify everything up front — humans don't think in complete specs, and even when they try, they forget the small details that turn into real problems once the project has grown. If the agent starts building from a thin description, it fills the gaps with silent guesses, and by the time those guesses turn out wrong, they're expensive to undo.

Brave Man flips the order: clarify exhaustively first, build later. The agent's job here is NOT to write code, scaffold files, or produce an implementation plan. Its only job is to run a structured interview until the project is fully understood, then write that understanding down as a single, clean, self-contained `prompt.md` file that a fresh agent session can execute later.

## When to Use This Skill

- Use when a user describes wanting to build a website, app, software, tool, or any kind of project.
- Use when the user request includes phrases like "build me a website", "I want an app for X", or "make a tool that does Y".
- Use BEFORE writing any code or implementation plan for a new build request.

## Step-by-Step Guide

1. **Triage** — a couple of quick questions to size up the project so question depth matches project complexity.
2. **Phased interview** — work through the relevant phases below, one at a time, asking batched questions per phase.
3. **Track completion** — maintain a visible checklist; don't move to synthesis until every relevant phase is closed (answered or explicitly defaulted).
4. **Synthesize** — write the final `prompt.md`. Do not generate an implementation plan artifact, scaffold a repo, or write any application code in this skill.
5. **Hand off** — tell the user to start a new chat, tag `prompt.md`, and ask the agent to execute it.

Never skip straight to building because the request "sounded simple." Simple requests still go through triage — triage is what decides how short the interview gets, not whether it happens.

## Phase 0: Triage

Ask 2-3 quick questions before anything else, to calibrate depth:

- Is this just for you, or will other people use/rely on it?
- Roughly how big is this in your head — a single page/script, a small app with a few features, or something with many moving parts (accounts, payments, multiple user roles, etc.)?
- Do you already have any strong preferences (language, framework, hosting, existing codebase) or is everything open?

Use the answers to decide which phases below need full depth, which need only one or two quick questions, and which can be skipped entirely with a stated default (e.g., a single static page skips Integrations & Auth entirely rather than asking about it).

## The phases

Work through these one phase at a time. Within a phase, ask questions in one batched round (3-5 questions), not one at a time. Skip or shrink phases that triage marked irrelevant — say so explicitly ("skipping auth since this has no accounts") rather than silently dropping them.

### Phase 1 — Purpose & users
- Who is this for, and what's the one thing it absolutely must let them do?
- What does success look like — what would make you say "yes, this is exactly what I wanted"?
- Is there an existing app/site/tool you're modeling this after, or anything you specifically want to avoid?

### Phase 2 — Core features & flows
- Walk me through what a user does step by step, from opening it to getting value out of it.
- Of everything you've mentioned, what's must-have for a first version versus nice-to-have later?
- Are there any features you're assuming are "obvious" that you haven't said out loud yet?

### Phase 3 — Data & content model
- What are the main "things" this app manages (e.g. posts, orders, users, files) and how do they relate to each other?
- Does data need to persist permanently, or is some of it temporary/session-only?
- Will the same data need to be seen differently by different users (e.g. private vs shared), or is it all visible to everyone the same way?

### Phase 4 — Tech stack & environment
- Any required language/framework, or should the agent pick what fits best?
- Where will this run — a specific hosting platform, local-only, mobile, desktop, browser?
- Does this need to fit into an existing codebase/repo, or is it starting fresh?

### Phase 5 — Integrations & auth
*(skip entirely if triage shows no accounts/external services needed — state that explicitly instead of asking)*
- Does this need user accounts/login at all? If so, simple email+password, or sign-in via Google/Apple/etc.?
- Does it need to talk to any outside service (payments, email sending, maps, AI APIs, etc.)?
- Are there multiple types of users with different permissions (e.g. admin vs regular user)?

### Phase 6 — Non-functional requirements
- Roughly how many people might use this at once — a handful, hundreds, way more?
- Any sensitive data involved (personal info, payme
