---
name: app-lifecycle
description: Planning a SaaS stage, 'what's next', 'where are we', calling a stage done: the detailed path from an idea to production, each stage with its done-when. 
category: Document Processing
source: antigravity
tags: [ai, agent, template, design, document, security, supabase, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/app-lifecycle
---


# App lifecycle — from an idea to a product in production

## Operational boundaries

Keep the scope, sandbox, credentials and approval settings supplied by the user or host. Obtain authorization before delegating, exposing project files to another provider, enabling connectors or hooks, using paid services or deploying. Use synthetic or redacted inputs for examples. Keep security reviews static and defensive, with findings and fixes grounded in source inspection.

## When to Use

Planning a SaaS stage, 'what's next', 'where are we', calling a stage done: the detailed path from an idea to production, each stage with its done-when.


**Start at the first stage whose done-when remains open.** This is the detailed SaaS path: each stage names its output, completion evidence and the skills explaining how to build it. Knowing the stage tells the agent what to build, what to defer, what done means and what to propose next. Pending owner previews stay visibly open while the next runnable phase starts; only exclusive owner decisions require waiting (§ What holds at every stage).

**Discovery and key screens come from the `propose` skill.** Its accepted artifact supplies stages 0–1's input. For any product, type `product-engineering-start-here` (Codex: `product-engineering-start-here`) for the same lifecycle in eight steps without the stack. Those steps are start, proposal, a plan for a complex change, build with reviews, owner click-through, release review, release and real users. Start at the first stage whose done-when remains open.

**Keep the stage principles and substitute your stack's vendor mechanisms.** The order, done-whens and rules holding at every stage are general. The mechanisms use Next.js (App Router), Supabase Postgres, Clerk and Netlify, with Vitest and Playwright.

## What binds, in order

1. **Keep product, design and release decisions with the owner.** The owner decides what the product is, picks between options, approves the design and legal text, and says go to a release. Phase previews record what they have tried without blocking coding. The agent proposes, builds and supplies evidence.
2. **Follow the product's plan; only the owner skips or defers a stage.** Its phases, and each stage's done-when, are the product's. These stages are defaults a plan may merge, split or reorder. Record any skip or deferral in the plan with the owner's decision and what brings it back; a broad go waives no stage it doesn't name. Unless the owner records otherwise, two orderings hold: design, with its artboards, comes before any app screen, even when setup moves first; and the front door (its block C) never moves behind the product's further feature phases (§ Order the work by what the owner will see).
3. **Read every stage through the product section of the agent instructions.** Above all, follow its declared shape (below); its scope and data constraints apply too. Wherever this skill names something the shape says the product does not have, the shape wins and that part is skipped.
4. **Use this skill's defaults and each stage's named implementation skills.**

## Find the stage you are in

| # | Stage | What it produces | Done when |
|---|---|---|---|
| 0 | Brief *(optional)* | the product section of the agent instructions (short; the shape declared) and the brief; what the idea leaves open becomes open entries in the decision log | the owner recognises the product in the product section |
| 1 | Screen options *(optional)* | open options on screens in the `propose` artifact; picks in the decision log | every decision the artifact covers has a pick |
| 2 | Design | the jobs map (each user job, its screen, that screen's one question and its primary action), the kit (tokens, primitives, the kit's README) and artboards for the first screens: two directions to pick from, or an existing design adopted; `app-stack` installed in every agent that builds screens | the owner approves the artboards, every raw value lives in the tokens, and every builder loads the method from its installed pack |
| 3 | Screens on sample data | the first screens, built from the kit, with sample data that fills every screen, behind the seams the real system will use, and the front door's screens with them (the landing at `/`, pricing on display where the product bills, and placeholder legal pages). The member's main screen sits at its own route, the member home, never at `/`. No database, no sign-in | the walkthrough, rendered pass, app-screen screenshot critique and scored audit passed (the `ui-design` skill, P0 and P1 fixed), then the owner approved the look and clicked through every state at phone and desktop width |
| 4 | Setup | the identity provider's development app (organizations on, in the organization shape), its test mode, the owner's own verification code and first test account; a development database project, the CLI reaching it by its connection string (never linked), the keys in `.env` | the app boots on development keys and t
