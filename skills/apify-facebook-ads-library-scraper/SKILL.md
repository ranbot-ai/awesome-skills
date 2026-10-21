---
name: apify-facebook-ads-library-scraper
description: Research Meta Ad Library ads by advertiser or keyword with creative links, dates and disclosed reach or spend through the harshmaur/facebook-ads-library-scraper Apify Actor. 
category: Document Processing
source: antigravity
tags: [api, mcp, claude, ai, agent, workflow, template, spreadsheet, image, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-facebook-ads-library-scraper
---


# Facebook Ads Library Scraper

Turn "what ads does X run" into one run of `harshmaur/facebook-ads-library-scraper` and return one row per ad. The Actor reads the public Meta Ad Library. It takes two kinds of input: an Ad Library search URL for a keyword, or a Facebook Page for one advertiser. The agent's job is to build the right URL and to cap the ad count.

Disclosure: the Actor is paid per result and is built by the skill author. Links carry no affiliate parameters.

## When to Use

Use to research public Meta ads by advertiser or keyword, export ad creative and dates, or review disclosed reach and spending.

## Example prompts

Prompts this skill handles:

- "Pull every active ad Gymshark runs in the US and sort them by how long they have been live."
- "Find ads for 'protein powder' in the UK that have run for more than 60 days, with their video links."
- "Export the last 30 days of ads from facebook.com/allbirds to a spreadsheet."
- "How much did political advertisers in Germany spend on ads about energy?"

Out of scope (the boundary):

- "Create or pause my Facebook ads" or "show my ad account ROAS" — use the Meta Marketing API with the user's own account.
- "Find TikTok or Google ads" — other ad libraries; use a different Actor.

## Prerequisites

- Apify account ([sign up](https://apify.com)). The free plan's monthly credit covers about 10,000 ads.
- Authentication via one of:
  - `apify login` (OAuth, if you use the Apify CLI)
  - `APIFY_TOKEN` environment variable
  - Token from [Apify Console → Settings → Integrations](https://console.apify.com/settings/integrations)
- Apify CLI (`npm install -g apify-cli`), or the Apify MCP server (see "Calling the Actor").

## Workflow

### Step 1 — Pick the input type

| The user gives you | Put in `urls` | Notes |
|---|---|---|
| A brand, an advertiser, a Page link | The Page URL: `https://www.facebook.com/<handle>`, a `profile.php?id=` link, or the numeric Page ID | All ads of that advertiser. Filter with the `scrapePageAds.*` fields below. |
| A keyword, product or topic | An Ad Library search URL (build it as shown below) | All advertisers whose ads match the words in that country. |
| An Ad Library URL the user copied | That URL, unchanged | It keeps every filter the user set on the site. |

Build a keyword search URL like this. Change only `country`, `q`, `active_status` and `search_type`:

```
https://www.facebook.com/ads/library/?active_status=active&ad_type=all&country=US&q=protein%20powder&search_type=keyword_unordered&media_type=all
```

- `country`: a 2-letter code (`US`, `GB`, `DE`), or `ALL`.
- `q`: URL-encoded words.
- `search_type`: `keyword_unordered` (all words, any order) or `keyword_exact_phrase`.
- `active_status`: `active`, `inactive` or `all`.
- `ad_type=political_and_issue_ads`: political and social-issue ads. Only these carry spend and impressions outside the EU and UK.

Filters for Page URLs only:

| Field | Values |
|---|---|
| `scrapePageAds.activeStatus` | `all` (default), `active`, `inactive` |
| `scrapePageAds.period` | `""` (all time), `last24h`, `last7d`, `last14d`, `last30d` |
| `scrapePageAds.sortBy` | `impressions_desc` (default), `most_recent` |
| `scrapePageAds.countryCode` | 2-letter code or `ALL` (default) |

Amounts and extras:

| Field | Meaning |
|---|---|
| `count` | Most ads for the whole run, over all URLs. Default 100. `0` means no limit: never send `0` without a cost check. |
| `limitPerSource` | Most ads per URL, so one big advertiser does not use up `count`. |
| `scrapeAdDetails` | `true` adds the advertiser text and the EU and UK transparency data: reach, age range, gender, countries. It makes the run slower. |
| `runTag` | A label copied onto every row. Useful when you merge runs. |

### Step 2 — Build the input

```json
{
  "urls": [{ "url": "https://www.facebook.com/gymshark" }],
  "scrapePageAds.activeStatus": "active",
  "scrapePageAds.countryCode": "US",
  "count": 200
}
```

Note the field names with a dot, for example `"scrapePageAds.activeStatus"`. They are flat keys, not nested objects. Fetch the live schema when a field is in doubt:

```bash
apify actors info "harshmaur/facebook-ads-library-scraper" --input --json \
  --user-agent apify-awesome-skills/apify-facebook-ads-library-scraper 2>/dev/null
```

### Step 3 — Estimate the cost, then run

The price is per ad in the dataset. There is no start fee, and `scrapeAdDetails` costs nothing extra:

| Apify plan | Per 1,000 ads |
|---|---|
| Free | $0.50 |
| Starter | $0.47 |
| Scale | $0.43 |
| Business and higher | $0.40 |

`cost ≈ count × $0.0005`. 1,000 ads cost at most $0.50. Under about 4,000 ads, run it. Above that, or with `count: 0`, state the estimate and get a yes first.

```bash
apify actors call "harshmaur/facebook-ads-library-scraper" \
  -i '{"urls":[{"url":"https://www.facebook.com/gymshark"}],"scrapePageAds.activeStatus":"active","count":200}' \
  --json \
  --user-agent apify-awesome-skills/apify-facebook-ads-library-scraper \
  2>/de
