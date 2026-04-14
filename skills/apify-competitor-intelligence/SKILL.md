---
name: apify-competitor-intelligence
description: Analyze competitor strategies, content, pricing, ads, and market positioning across Google Maps, Booking.com, Facebook, Instagram, YouTube, and TikTok. 
category: Creative & Media
source: antigravity
tags: [node, api, mcp, claude, ai, workflow, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-competitor-intelligence
---


# Competitor Intelligence

Analyze competitors using Apify Actors to extract data from multiple platforms.

## When to Use
- You need competitor benchmarks for content, reviews, pricing, ads, audience, or channel performance.
- The task involves selecting Apify Actors to compare competitors across maps, booking, social, or video platforms.
- You need structured competitor data plus synthesized takeaways for strategy or positioning.

## Prerequisites
(No need to check it upfront)

- `.env` file with `APIFY_TOKEN`
- Node.js 20.6+ (for native `--env-file` support)
- `mcpc` CLI tool: `npm install -g @apify/mcpc`

## Workflow

Copy this checklist and track progress:

```
Task Progress:
- [ ] Step 1: Identify competitor analysis type (select Actor)
- [ ] Step 2: Fetch Actor schema via mcpc
- [ ] Step 3: Ask user preferences (format, filename)
- [ ] Step 4: Run the analysis script
- [ ] Step 5: Summarize findings
```

### Step 1: Identify Competitor Analysis Type

Select the appropriate Actor based on analysis needs:

| User Need | Actor ID | Best For |
|-----------|----------|----------|
| Competitor business data | `compass/crawler-google-places` | Location analysis |
| Competitor contact discovery | `poidata/google-maps-email-extractor` | Email extraction |
| Feature benchmarking | `compass/google-maps-extractor` | Detailed business data |
| Competitor review analysis | `compass/Google-Maps-Reviews-Scraper` | Review comparison |
| Hotel competitor data | `voyager/booking-scraper` | Hotel benchmarking |
| Hotel review comparison | `voyager/booking-reviews-scraper` | Review analysis |
| Competitor ad strategies | `apify/facebook-ads-scraper` | Ad creative analysis |
| Competitor page metrics | `apify/facebook-pages-scraper` | Page performance |
| Competitor content analysis | `apify/facebook-posts-scraper` | Post strategies |
| Competitor reels performance | `apify/facebook-reels-scraper` | Reels analysis |
| Competitor audience analysis | `apify/facebook-comments-scraper` | Comment sentiment |
| Competitor event monitoring | `apify/facebook-events-scraper` | Event tracking |
| Competitor audience overlap | `apify/facebook-followers-following-scraper` | Follower analysis |
| Competitor review benchmarking | `apify/facebook-reviews-scraper` | Review comparison |
| Competitor ad monitoring | `apify/facebook-search-scraper` | Ad discovery |
| Competitor profile metrics | `apify/instagram-profile-scraper` | Profile analysis |
| Competitor content monitoring | `apify/instagram-post-scraper` | Post tracking |
| Competitor engagement analysis | `apify/instagram-comment-scraper` | Comment analysis |
| Competitor reel performance | `apify/instagram-reel-scraper` | Reel metrics |
| Competitor growth tracking | `apify/instagram-followers-count-scraper` | Follower tracking |
| Comprehensive competitor data | `apify/instagram-scraper` | Full analysis |
| API-based competitor analysis | `apify/instagram-api-scraper` | API access |
| Competitor video analysis | `streamers/youtube-scraper` | Video metrics |
| Competitor sentiment analysis | `streamers/youtube-comments-scraper` | Comment sentiment |
| Competitor channel metrics | `streamers/youtube-channel-scraper` | Channel analysis |
| TikTok competitor analysis | `clockworks/tiktok-scraper` | TikTok data |
| Competitor video strategies | `clockworks/tiktok-video-scraper` | Video analysis |
| Competitor TikTok profiles | `clockworks/tiktok-profile-scraper` | Profile data |

### Step 2: Fetch Actor Schema

Fetch the Actor's input schema and details dynamically using mcpc:

```bash
export $(grep APIFY_TOKEN .env | xargs) && mcpc --json mcp.apify.com --header "Authorization: Bearer $APIFY_TOKEN" tools-call fetch-actor-details actor:="ACTOR_ID" | jq -r ".content"
```

Replace `ACTOR_ID` with the selected Actor (e.g., `compass/crawler-google-places`).

This returns:
- Actor description and README
- Required and optional input parameters
- Output fields (if available)

### Step 3: Ask User Preferences

Before running, ask:
1. **Output format**:
   - **Quick answer** - Display top few results in chat (no file saved)
   - **CSV** - Full export with all fields
   - **JSON** - Full export in JSON format
2. **Number of results**: Based on character of use case

### Step 4: Run the Script

**Quick answer (display in chat, no file):**
```bash
node --env-file=.env ${CLAUDE_PLUGIN_ROOT}/reference/scripts/run_actor.js \
  --actor "ACTOR_ID" \
  --input 'JSON_INPUT'
```

**CSV:**
```bash
node --env-file=.env ${CLAUDE_PLUGIN_ROOT}/reference/scripts/run_actor.js \
  --actor "ACTOR_ID" \
  --input 'JSON_INPUT' \
  --output YYYY-MM-DD_OUTPUT_FILE.csv \
  --format csv
```

**JSON:**
```bash
node --env-file=.env ${CLAUDE_PLUGIN_ROOT}/reference/scripts/run_actor.js \
  --actor "ACTOR_ID" \
  --input 'JSON_INPUT' \
  --output YYYY-MM-DD_OUTPUT_FILE.json \
  --format json
```

### Step 5: Summarize Findings

After completion, report:
- Number of competitors analyzed
- File location and name
- Key compe
