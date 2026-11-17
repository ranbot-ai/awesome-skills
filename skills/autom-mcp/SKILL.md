---
name: autom-mcp
description: Get Google, Bing, Brave, DuckDuckGo and Yahoo results as JSON (web, news, maps, shopping, jobs, images, AI Mode) through Autom's MCP server. Use when the user chooses Autom. 
category: Development & Code Tools
source: antigravity
tags: [api, mcp, ai, agent, workflow, image, security, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/autom-mcp
---


# Autom MCP

## Overview

Use the Autom MCP tools to get search engine result pages as structured JSON:
Google web, news, maps, shopping, jobs, images, videos, autocomplete and AI
Mode, plus Bing, Brave, DuckDuckGo and Yahoo. Results keep the position, title,
link and snippet of each result, and accept country, language and location
settings, so the agent can see what a searcher in a given place sees.

The server requires an Autom API key. Search calls use credits from the account
that owns the key.

Other search skills in this catalog give an agent web results to read for
research. This skill returns the result page itself, per engine and per
vertical, for rank checks, local results, shopping prices and SERP comparisons.

## When to Use This Skill

- The user chooses Autom, or the Autom tools that are connected to the host.
- The user wants the Google results for a query in a given country, language or
  city, with positions.
- The user wants Google Maps places, Google Shopping offers, Google News, Google
  Jobs, images or videos for a query.
- The user wants the Google AI Mode answer for a query, or to compare the same
  query on Google, Bing, Brave, DuckDuckGo and Yahoo.

Respect an explicitly chosen provider. For general research where result
positions do not matter, a web search skill such as `serply-search-mcp` or
`parallel-search-mcp` fits better. This skill does not change search defaults or
configure servers automatically.

## Prerequisites

The host must already have a remote MCP connection to `https://mcp.autom.dev/`
with Streamable HTTP, and the user's API key in an `x-api-key` header. Keys are
issued in the [Autom dashboard](https://app.autom.dev). The same server is also
published as the `@automdev/mcp` npm package for stdio; it reads the key from the
`AUTOM_API_KEY` environment variable. See the
[server README](https://github.com/automdev/autom-mcp) for client examples.

Client configuration formats differ. Get the user's approval before you change
their agent configuration. Reference the key through the host's environment or
secret mechanism. Do not put it in a shared config file or in chat. Do not
replace an existing connection.

Use the host's tool discovery to confirm that the server exposes the tools named
below. Hosts can add a server prefix to the names. Installing this skill does not
install or connect the MCP server. To stop using the service, disable or remove
its connection in the host's MCP settings.

## How It Works

### 1. Establish the inputs

Get the query, the engine and where the search should come from. Results change
by country, language and location, so ask when the user gives none. Google tools
take `gl` (two-letter country, such as `us` or `fr`), `hl` (language, such as
`en` or `fr`) and, on several tools, `location` (a place name such as
`Paris, France`). `location` and `uule` cannot be used together.

To find valid codes, call `finder_google_countries`, `finder_google_languages`
or `finder_google_locations` with a `query`. Their descriptions mark them as
free.

### 2. Pick the tool

| Tool | Use | Credits |
| --- | --- | --- |
| `google_search` | Google web results; `tbs` for time filters, `page` | 1 |
| `google_search_light` | Organic Google results only, faster | 1 |
| `google_search_ai` | Google AI Mode: `text_blocks`, `references`, `shopping_results` | 3 |
| `google_search_autocomplete` | Suggestions for a partial query | 1 |
| `google_news` | News results | 1 |
| `google_maps` | Places with address, website and phone | 1 |
| `google_shopping` | Product listings with prices and merchants | 1 |
| `google_jobs` | Job listings; `next_page_token` for more | 1 |
| `google_images`, `google_videos` | Image and video results | 1 |
| `bing_search`, `brave_search`, `duckduckgo_search`, `yahoo_search` | Organic results on that engine | 1 |
| `brave_images`, `brave_videos` | Brave image and video results | 1 |
| `search` | Tries engines in order and returns the first organic results | 1 |
| `finder_google_countries`, `finder_google_languages`, `finder_google_locations` | Code lookups | free |
| `usage` | Credits used and balance | - |

Each tool description states its cost. If it differs from this table, use the
description. Inspect the connected tool schema before you add a parameter, and
use only fields that it supports. Every search tool also accepts `fields`, a
comma-separated list of response fields to keep (dot notation for nested
fields). It does not change the cost and keeps large results small.

Tell the user the total cost before a batch, for example 20 keywords in three
countries (60 calls). One call returns one page; each extra page is another call.

### 3. Read the result

Use the position of each organic result as returned. Do not re-rank results. Result
pages change with location and over time, so give the engine, country,
language, location and date with each finding. For `google_search_ai`,
report the answer text and its `references` separately.

Check tool 
