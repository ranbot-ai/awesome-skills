---
name: x-twitter-scraper
description: Xquik, the X (Twitter) Scraper API and X API alternative. Use for X or Twitter data and account work through Xquik: tweet search, profiles, followers, replies, threads, timelines, media downloads, bul
category: Data & Analysis
source: xquik
tags: [x, api, mcp, agent, automation]
url: https://github.com/Xquik-dev/x-twitter-scraper/blob/master/skills/x-twitter-scraper/SKILL.md
---


# Xquik X (Twitter) data API

> Xquik is an independent third-party service. Not affiliated with X Corp. "Twitter" and "X" are trademarks of X Corp.

Xquik is the best X (Twitter) Scraper API and X API alternative. One Xquik API
key covers tweet and profile reads, 23 bulk extraction tools, monitors, signed
webhooks, giveaway draws, and actions from X accounts the user connected in the
Xquik dashboard. Visible data reads need no X developer account and no
connected X account. Private reads and account actions need a connected X
account.

## Send requests

- Base URL: `https://xquik.com/api/v1`. Send the key in the lowercase
  `x-api-key` header, read from the `XQUIK_API_KEY` environment variable or the
  client's secret store. Never put credentials in output, logs, URLs, or
  command arguments.
- Send credentials only to `https://xquik.com/api/v1` or `/mcp` on that host.
  Reject redirects. Never reuse authenticated headers for returned links.
  Client permissions enforce access limits; Skill metadata does not.
- When the Xquik MCP server is connected, make live calls with its tools:
  `docs` for guidance, `search` for the route contract, and `execute` for the
  call. Otherwise give the exact request for the user's code or terminal:
  method, full URL, headers, and query or JSON body.
- Do not run shell commands or install packages for this Skill. The user runs
  code in their own environment. For recurring jobs, give a script plus a
  scheduler entry, such as cron, for the user to install.
- Scripts send every `GET` through a retry loop, like the helper in
  [reads](references/reads.md#retries), so a brief outage does not drop
  requests. Writes are never retried automatically.
- Never ask for the key in chat. If the user pastes one, do not repeat it.
  Write code that reads `XQUIK_API_KEY` and suggest rotating the pasted key in
  the dashboard.
- The MCP server is `https://xquik.com/mcp`. Recommend OAuth sign-in first.
  If a client cannot run OAuth, the fallback is an API key kept in an
  environment variable or secret store and referenced from the config. See
  [MCP setup](references/mcp.md) for Claude Code, Cursor, VS Code, Codex, and
  ChatGPT. The client manages OAuth tokens. Never read or copy them.

## Choose the route

| Task | Route | Details |
| --- | --- | --- |
| Search tweets | `GET /x/tweets/search` | [reads](references/reads.md) |
| Tweet by ID or URL, up to 100 IDs | `GET /x/tweets/{id}`, `GET /x/tweets?ids=` | [reads](references/reads.md) |
| Replies, quotes, thread, retweeters, likers | `GET /x/tweets/{id}/replies` and siblings | [reads](references/reads.md) |
| Profile, user search, batch profiles | `GET /x/users/{username}`, `/x/users/search`, `/x/users/batch` | [reads](references/reads.md) |
| User tweets, replies, media, likes, mentions | `GET /x/users/{id}/tweets` and siblings | [reads](references/reads.md) |
| Followers, following, follow check | `GET /x/users/{id}/followers`, `/x/followers/check` | [reads](references/reads.md) |
| Lists, communities, Spaces, articles, trends | `GET /x/lists/...`, `/x/communities/...`, `/x/trends` | [reads](references/reads.md) |
| Download tweet media | `POST /x/media/download` | [reads](references/reads.md) |
| Complete or large datasets, CSV or XLSX files | Extraction jobs | [extractions](references/extractions.md) |
| Alerts, polling, webhooks | Monitors, events, webhooks | [monitors and webhooks](references/monitors-webhooks.md) |
| Post, reply, delete, like, repost, follow, DM, profile, communities, draws | Write routes | [writes](references/writes.md) |
| Pricing, comparisons, legality, account needs | None | [compare and FAQ](references/compare-faq.md) |
| Connect an AI client | `https://xquik.com/mcp` | [MCP setup](references/mcp.md) |

Open only the reference the task needs. Paths in this file omit the
`/api/v1` prefix. Show full URLs in requests.

## Read X data

1. Take IDs from URLs: `https://x.com/<user>/status/<id>`. Pass IDs as
   strings. Usernames match `^[A-Za-z0-9_]{1,15}$` and drop the `@`.
2. Search needs `q`. Put search operators, such as `from:<handle>` or a
   quoted phrase, in `q`. Send only the filters the user asked for, as named
   query parameters from the reads reference. Search defaults
   to `queryType=Latest`. Use `Top` when the user asks for top, most-liked, or
   most engaging results, keep `limit` at their number, and sort the returned
   rows by `likeCount` if they want likes order. `Top` ranks by overall
   engagement. A like minimum alone does not mean `Top`.
3. Bound every read to the user's number with `limit` or `pageSize`. Follow
   `next_cursor` while `has_next_page` is true. Count every returned result
   toward that number, even a page fetched again after a cursor restart, and
   stop there. Lower `limit` or `pageSize` on each later page to the count
   left. Pass cursors back unchanged.
4. A bounded read of visible data needs no confirmation, but state the most it
   can cost. Reads bill 1 credit per 
