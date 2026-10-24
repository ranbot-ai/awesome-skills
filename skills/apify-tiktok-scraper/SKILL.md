---
name: apify-tiktok-scraper
description: Research TikTok videos, profiles, hashtags, comments and followers with engagement statistics through the harshmaur/tiktok-scraper Apify Actor. No TikTok login. 
category: Development & Code Tools
source: antigravity
tags: [api, mcp, claude, ai, agent, workflow, image, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-tiktok-scraper
---


# TikTok Scraper

Answer a TikTok question with one run of `harshmaur/tiktok-scraper`. One Actor reads profiles, hashtags, search, video links, sounds, comments and followers, so the job is to pick the input lists, set the per-target count, and keep paid add-ons off unless the user asks for them.

Disclosure: the Actor is paid per result and is built by the skill author. Links carry no affiliate parameters.

## When to Use

Use for TikTok video, creator, hashtag, comment and follower research, or exports with engagement statistics.

## Example prompts

Prompts this skill handles:

- "Get the 30 newest videos from @khaby.lame and @mrbeast with view and like counts."
- "Top TikTok videos about iced matcha from the past week, sorted by likes."
- "Export 200 comments with replies from this video: https://www.tiktok.com/@user/video/123..."
- "Is this creator brand safe? Check their last 20 videos and tell me which ones look sponsored."
- "Videos under #booktok from September with at least 50,000 likes, exact tag only."

Out of scope (the boundary):

- "Post, like or comment on TikTok" — the Actor only reads public data.
- "Scrape TikTok Shop products" or "TikTok ads" — use a TikTok Shop or ads Actor from the Apify Store.
- "Show me @user's stories" or a private account — not visible without a login, so the Actor cannot read them.

## Prerequisites

- Apify account ([sign up](https://apify.com)). AI add-ons need a paid Apify plan; on the free plan they are ignored.
- Authentication via one of:
  - `apify login` (OAuth, if you use the Apify CLI)
  - `APIFY_TOKEN` environment variable
  - Token from [Apify Console → Settings → Integrations](https://console.apify.com/settings/integrations)
- Apify CLI (`npm install -g apify-cli`), or the Apify MCP server (see "Calling the Actor").

## Workflow

### Step 1 — Pick the input lists

You can mix several lists in one run.

| The user gives you | Field | Notes |
|---|---|---|
| Usernames or profile links | `profiles` | With or without `@`. Sort with `profileSorting` (`latest`, `popular`, `oldest`). Set `excludePinnedPosts: true` so "latest" is really latest. |
| Hashtags | `hashtags` | With or without `#`. TikTok mixes in videos without the tag; `hashtagMatch: "exact"` drops them, and dropped videos are not charged. |
| Keywords | `searchQueries` | `searchSection`: `""` or `"/video"` for videos, `"/user"` for accounts. Videos: `videoSearchSorting` (`MOST_RELEVANT`, `MOST_LIKED`, `LATEST`) and `videoSearchDateFilter` (`ALL_TIME`, `PAST_24_HOURS`, `PAST_WEEK`, `PAST_MONTH`, `LAST_3_MONTHS`, `LAST_6_MONTHS`). |
| Video or photo post links, `vm.tiktok.com` links, video IDs | `postURLs` | Add `scrapeRelatedVideos: true` for the videos TikTok recommends next. |
| Sound links or IDs | `musics` | Videos that use the sound. |
| Any other TikTok link | `startUrls` | The Actor works out the type. |

Then set the amounts:

| Field | Meaning |
|---|---|
| `resultsPerPage` | Videos **per** profile, hashtag, keyword or sound. **Default is 1**: always set it. |
| `maxItems` | Optional hard cap on all rows of the run: videos, comments, profiles and followers together. |
| `commentsPerPost`, `maxRepliesPerComment`, `topLevelCommentsPerPost` | Comments per video, replies per comment, cap on top-level comments. |
| `maxFollowersPerProfile`, `maxFollowingPerProfile` | Follower or following accounts per profile in `profiles`. |
| `maxProfilesPerQuery` | Accounts per keyword when `searchSection` is `"/user"`. Default 10. |

Free filters (they work together, on every list):

- `oldestPostDateUnified`: a date (`"2026-09-01"`) or a number of days (`"30"`, `"2 weeks"`).
- `newestPostDate`: a date.
- `leastDiggs`, `mostDiggs`: likes range.

Paid add-ons. Set them only when the user asks:

- `downloadSubtitlesOptions`: `DOWNLOAD_SUBTITLES` (TikTok captions, free), `DOWNLOAD_AND_TRANSCRIBE_VIDEOS_WITHOUT_SUBTITLES` or `TRANSCRIBE_ALL_VIDEOS` (AI transcript, paid).
- `aiAnalysis: true` (+ up to 20 `aiQuestions`), `aiVideoSummary`, `aiVideoDescription`.
- `shouldDownloadVideos: true` (watermark-free MP4). Covers, slideshow images, avatars and sound covers are free.


### Step 2 — Build the input

```json
{
  "searchQueries": ["iced matcha"],
  "videoSearchSorting": "MOST_LIKED",
  "videoSearchDateFilter": "PAST_WEEK",
  "resultsPerPage": 30
}
```

The author describes compatibility with `clockworks/tiktok-scraper`; verify the actual input schema rather than assuming interchangeability. Fetch the live schema when a field is in doubt:

```bash
apify actors info "harshmaur/tiktok-scraper" --input --json \
  --user-agent apify-awesome-skills/apify-tiktok-scraper
```

### Step 3 — Estimate the cost, then run

| Row or add-on | Price |
|---|---|
| Video | $0.35 per 1,000 |
| Comment or reply | $0.20 per 1,000 |
| Follower or following account | $0.25 per 1,000 |
| Profile (one per profile in `profiles`, and each account from `"/user"` search) | $4.00 per 1,000 |
| `aiAnalysis` | $1.50 per 1,000 videos |
| AI 
