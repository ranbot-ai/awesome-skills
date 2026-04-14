---
name: agentphone
description: Build AI phone agents with AgentPhone API. Use when the user wants to make phone calls, send/receive SMS, manage phone numbers, create voice agents, set up webhooks, or check usage — anything relate
category: AI & Agents
source: antigravity
tags: [python, javascript, node, api, claude, ai, agent, llm, gpt, automation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agentphone
---


# AgentPhone

AgentPhone is an API-first telephony platform for AI agents. Give your agents phone numbers, voice calls, and SMS — all managed through a simple API.

## When to Use
- Use when the user wants to create or manage AI phone agents, voice agents, or telephony automations
- Use when the user needs to buy, assign, release, or inspect phone numbers tied to an agent workflow
- Use when the user wants to place outbound calls, inspect transcripts, or send and receive SMS through AgentPhone
- Use when the user is configuring webhooks, hosted voice mode, or account-level usage for AgentPhone
- Use only with explicit user intent before actions that spend money, send messages, place calls, or release phone numbers

**Base URL:** `https://api.agentphone.to/v1`

**Docs:** [docs.agentphone.to](https://docs.agentphone.to)

**Console:** [agentphone.to](https://agentphone.to)

---

## How It Works

AgentPhone lets you create AI agents that can make and receive phone calls and SMS messages. Here's the full lifecycle:

1. You sign up at [agentphone.to](https://agentphone.to) and get an API key
2. You create an **Agent** — this is the AI persona that handles calls and messages
3. You buy a **Phone Number** and attach it to the agent
4. You configure a **Webhook** (for custom logic) or use **Hosted Mode** (built-in LLM handles the conversation)
5. Your agent can now make outbound calls, receive inbound calls, and send/receive SMS

```
Account
└── Agent (AI persona — owns numbers, handles calls/SMS)
    ├── Phone Number (attached to agent)
    │   ├── Call (inbound/outbound voice)
    │   │   └── Transcript (call recording text)
    │   └── Message (SMS)
    │       └── Conversation (threaded SMS exchange)
    └── Webhook (per-agent event delivery)
Webhook (project-level event delivery)
```

### Voice Modes

Agents operate in one of two modes:

- **`hosted`** — The built-in LLM handles the conversation autonomously using the agent's `system_prompt`. No server required. This is the easiest way to get started — just set a prompt and make a call.
- **`webhook`** (default) — Inbound call/SMS events are forwarded to your webhook URL for custom handling. Use this when you need full control over the conversation logic.

---

## Quick Start

### Step 1: Get Your API Key

Sign up at [agentphone.to](https://agentphone.to). Your API key will look like `sk_live_abc123...`.

### Step 2: Create an Agent

```bash
curl -X POST https://api.agentphone.to/v1/agents \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Support Bot",
    "description": "Handles customer support calls",
    "voiceMode": "hosted",
    "systemPrompt": "You are a friendly customer support agent. Help the caller with their questions.",
    "beginMessage": "Hi there! How can I help you today?"
  }'
```

**Response:**

```json
{
  "id": "agent_abc123",
  "name": "Support Bot",
  "description": "Handles customer support calls",
  "voiceMode": "hosted",
  "systemPrompt": "You are a friendly customer support agent...",
  "beginMessage": "Hi there! How can I help you today?",
  "voice": "11labs-Brian",
  "phoneNumbers": [],
  "createdAt": "2025-01-15T10:30:00.000Z"
}
```

### Step 3: Buy a Phone Number

```bash
curl -X POST https://api.agentphone.to/v1/numbers \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "country": "US",
    "areaCode": "415",
    "agentId": "agent_abc123"
  }'
```

**Response:**

```json
{
  "id": "pn_xyz789",
  "phoneNumber": "+14155551234",
  "country": "US",
  "status": "active",
  "agentId": "agent_abc123",
  "createdAt": "2025-01-15T10:31:00.000Z"
}
```

Your agent now has a phone number. It can receive inbound calls immediately.

### Step 4: Make an Outbound Call

```bash
curl -X POST https://api.agentphone.to/v1/calls \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "agent_abc123",
    "toNumber": "+14155559999",
    "systemPrompt": "Schedule a dentist appointment for next Tuesday at 2pm.",
    "initialGreeting": "Hi, I am calling to schedule an appointment."
  }'
```

**Response:**

```json
{
  "id": "call_def456",
  "agentId": "agent_abc123",
  "fromNumber": "+14155551234",
  "toNumber": "+14155559999",
  "direction": "outbound",
  "status": "in-progress",
  "startedAt": "2025-01-15T10:32:00.000Z"
}
```

The AI will hold the entire conversation autonomously based on your prompt. Check the transcript after the call ends.

### Step 5: Check the Transcript

```bash
curl https://api.agentphone.to/v1/calls/call_def456/transcript \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Response:**

```json
{
  "data": [
    {
      "id": "tx_001",
      "transcript": "Hi, I am calling to schedule an appointment.",
      "response": null,
      "confidence": 0.95,
      "createdAt": "2025-01-15T10:32:01.000Z"
    },
    {
      "id": "tx_002",
      "transcript": "Sure, what day works for
