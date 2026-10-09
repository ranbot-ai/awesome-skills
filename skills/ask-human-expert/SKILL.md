---
name: ask-human-expert
description: Ask real executives and domain experts a question through Instant Expert for a written answer or short call: practitioner knowledge, customer discovery. Free test mode; live sends need approval. 
category: AI & Agents
source: antigravity
tags: [markdown, api, mcp, claude, ai, agent, security, stripe, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ask-human-expert
---


# Ask a Human Expert

## Overview

Instant Expert sends a paid ask from the user's account to real professionals: executives, operators and domain experts it finds from a description, or one specific person the user names. Each ask is a question for a written or voice answer, or a 15 to 60 minute call. The person is paid only if they answer or book, and the user is charged only then. Use it for knowledge work (judgment and first-hand experience from specific people), not errands or physical tasks.

The agent drives Instant Expert's MCP tools. When they aren't connected, it calls the free test server with `curl`, so the whole flow can be tried with no account or card. Adapted from the official skill, which also bundles a small test-mode helper script: https://github.com/Instant-Expert/skills

## When to Use This Skill

- Use when the answer needs a practitioner's experience rather than a web page: "How long did SOC 2 Type II take you?", "How do claims teams at mid-size insurers triage?"
- Use for customer discovery, user interviews, expert input, or a first conversation with a kind of buyer.
- Use when the user names someone to reach: "Jane Doe, VP of Sales at Acme", a LinkedIn URL or an email.
- Use when the user asks whether anyone answered an earlier ask.
- Do not use to find personal contact details, to get confidential or material non-public information, for physical tasks, or to message people the user hasn't approved.

## How It Works

### Step 1: Pick the mode

If the session already has the Instant Expert MCP tools (`search_people`, `queue_requests`, `prepare_request_order` and so on), call them directly. A result with `"test_mode": true` came from test mode; anything else is the user's live account.

Otherwise start a free 24-hour test sandbox. No account or card is needed, and each network can start 5 an hour, so reuse the token until it expires:

```bash
mkdir -p ~/.config/instant-expert
curl -sS -X POST https://instant.expert/api/sandbox -o ~/.config/instant-expert/sandbox.json
```

The saved JSON has `token`, `expires_at` and `mcp_url`. Call a tool by posting a JSON-RPC `tools/call` to the test server. It is stateless, so no `initialize` step is needed:

```bash
curl -sS https://instant.expert/mcp/test \
  -H "Authorization: Bearer $(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' ~/.config/instant-expert/sandbox.json)" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_requests","arguments":{}}}'
```

The answer is in `result.structuredContent` (the same JSON is in `result.content[0].text`). `result.isError: true` means the tool rejected the call; read its message. Use `"method":"tools/list"` to see every tool and its arguments. An HTTP 401 means the sandbox expired, so start a new one.

Test mode has about 300 fictional people at fictional companies, so a niche search comes back with the closest fictional matches. Invitations are recorded instead of sent, the fictional people answer within seconds, and orders use a Stripe test card. Nothing reaches a real person or moves real money. Tell the user once that results are simulated.

### Step 2: Choose who to ask

Tools that start work (`search_people`, `import_people`, `queue_requests`) return a `job_id`. Poll `get_job`, waiting `poll_after_seconds` between calls, until `status` is `succeeded` or `failed`. Give every new operation its own `idempotency_key`, and reuse a key only to retry the same call.

- A named person with a LinkedIn URL or email: skip searching and pass `people` to `queue_requests`, for example `[{"linkedin_url": "https://www.linkedin.com/in/..."}]`.
- A named person with only a name and company: call `import_people` with `people` set to `[{"name": "...", "company": "..."}]`, then `get_search`. If there's no match, ask the user for a LinkedIn URL or email.
- A kind of person: call `search_people` once with the whole request, including how many people and any exclusions, then read the list with `get_search` (`page_size: 100`).
- Only a goal ("we're building X, who should we talk to?"): call `plan_outreach` with a `description`, let the user pick an audience, then run its `search_query` through `search_people`.

### Step 3: Draft the ask

Call `queue_requests` with `search_id` (plus `person_profile_ids` to keep a subset) or `people`, and:

- `message`: the question, in the user's words, up to 500 characters. Leave the price out; the invitation states it.
- `request_type`: `text_voice_note` for a written or voice answer, or `call` with `call_duration_minutes` of 15, 30, 45 or 60.
- `offer_cents`, `max_spend_cents` and an `idempotency_key`.

Poll `get_job` for the `draft_id`.

### Step 4: Preview, approve and send

Call `prepare_request_order` with the `draft_id` (for a call, also the user's IANA `time_zone`, such as `America/New_York`). Show the user the recipients, message, `pricing_summary`, total cap, card, payment m
