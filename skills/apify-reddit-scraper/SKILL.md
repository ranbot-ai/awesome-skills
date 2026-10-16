---
name: apify-reddit-scraper
description: Scrape Reddit posts, comments, subreddits and users with the harshmaur/reddit-scraper Apify Actor. No Reddit API key. Keyword search, date windows, full threads. 
category: Document Processing
source: antigravity
tags: [api, mcp, claude, ai, agent, workflow, document, image, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-reddit-scraper
---


# Reddit Scraper

Turn a plain-language Reddit request into one run of `harshmaur/reddit-scraper` and hand back structured posts, comments, users or communities. One Actor covers search, subreddit listings, permalinks, user profiles and community metadata, so routing is about picking the right **input field**, not the right Actor.

Disclosure: the Actor this skill routes to is paid (pay per result) and built by the skill author. Links carry no affiliate parameters.

## When to Use

- The user wants Reddit posts, comments, subreddits or user profiles as structured data.
- The user wants to monitor a brand, product or competitor on Reddit, or track mentions since a date.
- The user wants every comment from a thread, or the newest posts from one or more subreddits.
- The user lost access to the Reddit API or Reddit RSS feeds and needs the same data without an API key.

## Example prompts

Prompts this skill handles:

- "Find every Reddit post from the last 30 days where someone asks for a Notion alternative, and pull the comments."
- "Scrape the newest 200 posts in r/SaaS and r/startups."
- "Give me all comments on this thread: https://www.reddit.com/r/webdev/comments/abc123/..."
- "Track mentions of `Linear` and `Jira` on Reddit since 2026-08-01 and send each hit to my Slack channel."
- "What has u/spez posted recently?"

Out of scope (the boundary):

- "Post a reply in r/startups" — this Actor only reads Reddit. Use the Reddit API with the user's own account.
- "Find Reddit threads *about* the pain of managing invoices" — Reddit search is literal keyword matching, not semantic. Expand the topic into 3–8 short literal keywords first (see Step 1), then run one search per keyword.

## Prerequisites

- Apify account ([sign up](https://apify.com)); the free plan covers small runs.
- Authentication via one of:
  - `apify login` (OAuth, if using the Apify CLI)
  - `APIFY_TOKEN` environment variable
  - Token from [Apify Console → Settings → Integrations](https://console.apify.com/settings/integrations)
- Apify CLI (`npm install -g apify-cli`), or the Apify MCP server (see "Calling the Actor").

## Workflow

### Step 1 — Classify the request and pick input fields

| User gives you | Field to use | Notes |
|---|---|---|
| Keywords, a brand, a product, a phrase | `searchTerms` (array) | One search per term, each with its own `maxPostsCount`. Keep terms short and literal (`"notion alternative"`, not a sentence). Free plans search the first 40 terms per run. |
| Keywords + "only in r/X" | `searchTerms` + `withinCommunity` | Accepts `developers`, `r/developers` or the full subreddit URL. |
| A subreddit to scrape in bulk | `subredditUrls` (array of names or community URLs) | Fetches far more posts than a plain listing. **Never put post permalinks here** — they are dropped silently and the run finishes with 0 items. |
| Post, user-profile, subreddit or search-page URLs | `startUrls` (array of `{ "url": ... }`) | Search options (sort/time/community) do NOT apply to these. `/s/` share links work too; the Actor resolves them. |
| "since <date>" / "between <dates>" / "last month" / "past week" | `postedAfter`, `postedBefore` (`YYYY-MM-DD`) | Relative periods too: "last month" → `postedAfter` = today − 1 month. Also `commentedAfter` / `commentedBefore` for comments. Results are fetched newest-first and stop early once older than the window; `searchSort` and `searchTime` are ignored while a date is set. |
| "with comments" / "full thread" | `crawlCommentsPerPost: true` + `maxCommentsPerPost` | Multiplies result count and cost — see gotchas. |
| "comments that mention X" | `searchComments: true`, `searchPosts: false` | Comment search across Reddit. |
| "which subreddits are about X" | `searchCommunities: true` | Returns `dataType: "community"` rows. |
| "send to Slack / Notion / Sheets" | `mcpConnector` + `mcpTarget` (+ `mcpMessage`) | Requires an authorized MCP connector in the user's Apify account; see `references/input-mapping.md`. |

When the user's phrase is descriptive rather than literal ("people frustrated with their CRM"), draft 3–8 literal keywords (`"CRM sucks"`, `"switching from HubSpot"`, `"CRM recommendation"`), put them in the run section of your answer (Step 3), and run them as `searchTerms`.

### Step 2 — Build the input

Start from these defaults and change only what the request needs:

```json
{
  "searchTerms": ["notion alternative"],
  "searchPosts": true,
  "searchComments": false,
  "searchCommunities": false,
  "searchSort": "new",
  "searchTime": "month",
  "maxPostsCount": 50,
  "crawlCommentsPerPost": false,
  "maxCommentsPerPost": 50,
  "includeNSFW": false
}
```

- `searchSort`: `new` for monitoring, `relevance` for precise matching, `top` / `hot` for what performed, `comments` for the most discussed.
- `searchTime`: `hour` | `day` | `week` | `month` | `year` | `all`. When the user names a period — a date or a relative one like "last month", "past week" — you have two options, and you must pick one 
