---
name: cloro-mcp
description: Get Google results with the AI Overview, and ChatGPT, Google AI Mode, Bing AI Mode and Gemini answers with their cited sources, through cloro's hosted MCP server. Use when the user chooses cloro. 
category: Development & Code Tools
source: antigravity
tags: [api, mcp, ai, agent, gpt, workflow, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cloro-mcp
---


# cloro MCP

## Overview

Use the cloro MCP tools to see what an AI assistant or Google shows for a prompt
or query, from a chosen country: the answer text and the sources it cites. The
tools return Google organic results with the AI Overview, and answers from
ChatGPT, Google AI Mode, Bing AI Mode and Gemini. Use the result to check if a
brand, page or domain appears in an answer, and which sources an answer cites.

The server requires a cloro account. Each call uses credits from that account.
The Free plan gives 500 credits a month.

Other search skills in this catalog return web results for research. This skill
returns what AI answers show to users, so it is for AI visibility checks and
answer comparison, not for general web research.

## When to Use This Skill

- The user chooses cloro, or the cloro tools that are connected to the host.
- The user wants to know what ChatGPT, Google AI Mode, Bing AI Mode or Gemini
  answers for a prompt, and which sources the answer cites.
- The user wants the Google results and the AI Overview for a query in a given
  country.
- The user wants to compare an AI answer with the Google results for the same
  topic.

Respect an explicitly chosen provider. For plain web research without AI answers,
a web search skill such as `serply-search-mcp` or `keenable-search-mcp` costs
less. This skill does not change search defaults or configure servers
automatically.

## Prerequisites

The host must already have a remote MCP connection to `https://mcp.cloro.dev/mcp`
with Streamable HTTP. The server accepts OAuth (the user signs in to cloro in the
browser) or a cloro API key in an `Authorization: Bearer` header. Keys are issued
at [dashboard.cloro.dev](https://dashboard.cloro.dev/api-keys?utm_source=agentic-awesome-skills&utm_medium=byok).
See the [cloro MCP guide](https://cloro.dev/docs/integrations/mcp?utm_source=agentic-awesome-skills&utm_medium=byok)
for client examples. Client configuration formats differ. Get the user's approval
before you change their agent configuration. Prefer OAuth. If the user uses a key,
reference it through the host's environment or secret mechanism. Do not put it in
a shared config file or in chat. Do not replace an existing connection.

Use the host's tool discovery to confirm that the server exposes these tools.
Hosts can add a server prefix to the names.

- `scrape_google`
- `scrape_chatgpt`
- `scrape_google_ai_mode`
- `scrape_bing_aimode`
- `scrape_gemini`
- `resolve_google_redirect`
- `list_countries`

The server also exposes tools that this skill does not cover. Use only the tools
named above. Installing this skill does not install or connect the MCP server. To
stop using the service, disable or remove its connection in the host's MCP
settings.

## How It Works

### 1. Establish the inputs

Get the prompt or query and the country. The country is an ISO 3166-1 alpha-2
code, such as `US` or `DE`. If the user gives no country, ask. Do not guess,
because answers and results change by country. Call `list_countries` with a
`model` (`chatgpt`, `aimode`, `bing_aimode`, `gemini`, `google` or
`aioverview`) to check that an engine supports the country. `list_countries`
costs no credits.

Use the words that a real user would type. One call gives one answer. AI answers
change between runs, so say that one result is one sample.

### 2. Pick the tool

| Tool | Main arguments | Credits |
| --- | --- | --- |
| `scrape_google` | `query`, `gl`, optional `include.aioverview: true` | 5, or 7 with the AI Overview |
| `scrape_chatgpt` | `prompt`, `country` | 7 |
| `scrape_google_ai_mode` | `prompt`, `gl` | 6 |
| `scrape_bing_aimode` | `prompt`, `country` | 6 |
| `scrape_gemini` | `prompt`, `country` | 6 |
| `resolve_google_redirect` | `url` (a `redirectLink` value) | 1 |
| `list_countries` | optional `model` | 0 |

Each result shows the credits charged and the credits that remain. Leave the
other `include` flags unset unless the user needs those fields; some of them add
credits. Inspect the connected tool schema before you add a parameter, and use
only fields that it supports. Each tool description states its cost. If the cost
in the description is different from this table, use the description.

`scrape_chatgpt` makes ChatGPT search the web by default, so the answer has
sources. To see the answer that ChatGPT gives without that, set
`disableWebSearch: true`. Sources can then be empty.

Tell the user the total credit cost before you run many calls, for example one
prompt on three engines in four countries (12 calls). Calls wait for the answer,
up to about five minutes each. For large or scheduled jobs, point the user to
cloro's async API instead of a loop of tool calls.

### 3. Read the result

- AI answers (`scrape_chatgpt`, `scrape_google_ai_mode`, `scrape_bing_aimode`,
  `scrape_gemini`): use `text` for the answer and `sources` for the cited pages.
  Each source has `position`, `label` and `url`. Count every item in `sources`
  as a cited source. Do not filter on the 
