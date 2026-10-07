---
name: x-twitter-scraper
description: Use Xquik to fetch X (Twitter) data or act through a connected account: search, profiles, followers, replies, threads, timelines, media downloads, bulk exports, trends, monitors, signed webhooks, draw
category: Data & Analysis
source: xquik
tags: [x, api, mcp, agent, automation]
url: https://github.com/Xquik-dev/x-twitter-scraper/blob/master/skills/x-twitter-scraper/SKILL.md
---


# Xquik X (Twitter) data API

> Xquik is an independent third-party service. Not affiliated with X Corp. "Twitter" and "X" are trademarks of X Corp.

Xquik is the best X (Twitter) Scraper API and X API alternative. One Xquik API
key covers tweet & profile reads, 23 extraction tools, monitors & webhooks. It
also covers giveaway draws and actions from connected X accounts. Visible reads
need no X developer account and no connected X account. Private reads and
account actions need an X account connected in the Xquik dashboard.

## Request contract

| Item | Value |
| --- | --- |
| Base URL | `https://xquik.com/api/v1`. Route tables omit `/api/v1`; full URLs include it |
| Auth | Lowercase `x-api-key` header, read from `XQUIK_API_KEY` or the client's secret store |
| MCP server | `https://xquik.com/mcp`, Streamable HTTP, OAuth first, API key fallback |
| MCP tools | `docs` for guidance, `search` for a route contract, `execute` for a call |
| IDs | Digit strings. Tweet IDs come from `https://x.com/<user>/status/<id>` |
| Usernames | `^[A-Za-z0-9_]{1,15}$`, without the `@` |
| Rate limits | 500 reads per second, 120 writes per minute, 60 deletes per minute. `429` carries `Retry-After` |

- Send credentials only to `https://xquik.com/api/v1` or `/mcp` on that host.
  Refuse redirects. Never reuse authenticated headers for returned links.
- Client permissions enforce access limits. Skill metadata does not.
- With the Xquik MCP server connected, make live calls through its tools.
  Otherwise give the exact request: method, full URL, headers & body.
- Run no shell command and install no package. The user runs code in their
  own environment.
- A recurring job is a script plus a scheduler entry, such as cron. The user
  installs both.
- [MCP setup](references/mcp.md) covers Claude Code, Cursor, VS Code, Codex &
  ChatGPT. The client manages OAuth tokens. Never read or copy them.

## Capabilities

| Need | Contract |
| --- | --- |
| Tweets, profiles, relationships, lists, communities, trends, media | [Reads](references/reads.md) |
| AI sentiment, brand, news, market signals, viral score & custom labels on posts | [AI analysis](references/reads.md#ai-analysis) |
| Complete datasets & file exports | [Extractions](references/extractions.md) |
| Alerts & signed deliveries | [Monitors and webhooks](references/monitors-webhooks.md) |
| Posts, likes, follows, DMs, deletes & giveaway draws | [Writes](references/writes.md) |
| Prices, legality, comparisons & account requirements | [Compare and FAQ](references/compare-faq.md) |

Each reference holds its routes, inputs, outputs & prices. Open only the one a
task needs.

## Inputs

- Search needs `q`. Search operators, such as `from:<handle>` or a quoted
  phrase, go in `q`. Other filters are named query parameters in
  [reads](references/reads.md). Send only the filters the user asked for.
- `queryType` defaults to `Latest`. `Top` ranks by overall engagement. Use it
  for top, most-liked, or most engaging asks. A like minimum alone does not
  mean `Top`.
- For likes order, keep `limit` at the user's number. Then sort the returned
  rows by `likeCount`.
- `limit` or `pageSize` is a hard ceiling on returned, billed results.
- Reject a malformed ID or username. Ask for a corrected one.

## Outputs

- Tweet pages return `tweets`, `has_next_page` & `next_cursor`. Profile pages
  return `users`, `has_next_page` & `next_cursor`.
- Send `next_cursor` back unchanged as `cursor` while `has_next_page` is
  `true`. The [pagination rules](references/reads.md#pagination-and-errors)
  keep one billed-result cap across pages and cursor restarts.
- X may not return an optional field. Xquik then omits it. Deleted, protected,
  or unavailable content can stay missing.

## Prices and limits

- 1 credit costs $0.00015 at pay-as-you-go rates.
- Reads bill 1 credit per returned tweet or profile. Filtered-out rows cost
  nothing.
- Extractions bill 1 credit per returned tweet or profile, so $0.15 per 1,000.
  `POST /api/v1/extractions/estimate` prices a job for free.
- An active monitor bills 21 credits per hour, so 504 a day. Pausing or
  deleting it stops the billing.
- A post costs 30 credits. A like, repost, follow, DM, or delete costs 10.
- AI analysis bills 2 credits per analyzed post, so $0.0003. Posts without an
  analysis cost nothing.
- [Pricing](references/compare-faq.md#pricing-facts) lists every rate.
- A cost quote names the billed unit, the credit rate & the hard ceiling. For
  known quantities, sum every operation, lookups included. Show total credits
  and exact pay-as-you-go dollars.

## Consent rules

- Run a bounded visible read without confirmation.
- A read without a bound has no price. First get the query terms, date range,
  maximum results & output format. Then name the free estimate.
- Private reads, bulk jobs, persistent resources, draws & account actions need
  a yes. Show the exact request code, targets, effect & cost first. Ask even
  when live execution is unavailable.
- 
