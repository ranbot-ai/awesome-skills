---
name: hasdata-cli
description: Command-line access to search, scraping, and structured web data. 
category: AI & Agents
source: antigravity
tags: [markdown, api, ai, agent, llm, workflow, image, rag, seo, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/hasdata-cli
---


# hasdata

Use the `hasdata` CLI for real-time web data. One subcommand per API — flags, enums, defaults are derived from the live schema at `api.hasdata.com/apis`.

## When to Use

Use this skill when:

- The user wants to use the HasData CLI.
- The user needs current web data from the command line.
- The user wants to automate data collection in scripts.
- The user wants to retrieve search, ecommerce, travel, or local business data.
- The user needs web-page scraping through the CLI.

## Prerequisites

- `command -v hasdata` — if missing, download the installer from `https://raw.githubusercontent.com/HasData/hasdata-cli/main/install.sh`, inspect it, then run it locally with `sh install.sh`.
- One-time setup: the user runs `hasdata configure`, pastes their API key, and it's saved to `~/.hasdata/config.yaml` (mode 0600). Every future call picks it up automatically.
- If a call fails with `no API key configured`, the user hasn't run `hasdata configure` yet — tell them to. **Never invent a key.**

## Quick start

```bash
hasdata <api> --flag value [--flag value ...] --raw | jq .
```

Always pass `--raw` when piping to `jq` (skips pretty-print and TTY detection). Use `--pretty` only for human-readable terminal output.

## Picking the right subcommand

| User intent | Subcommand |
| --- | --- |
| Web search ("what does Google say about…") | `google-serp` (full features) or `google-serp-light` (cheap, single page) |
| Latest news | `google-news` |
| AI Mode SERP | `google-ai-mode` |
| Shopping / product prices | `google-shopping` (broad), `amazon-search` / `amazon-product` (Amazon), `shopify-products` (Shopify) |
| Immersive product page | `google-immersive-product` |
| Maps / places / reviews | `google-maps`, `google-maps-place`, `google-maps-reviews`, `google-maps-photos`, `google-maps-posts` |
| Yelp / YellowPages local data | `yelp-search`, `yelp-place`, `yellowpages-search`, `yellowpages-place` |
| Real-estate listings (homes for sale/rent/sold) | `zillow-listing`, `redfin-listing` |
| Real-estate single property deep dive | `zillow-property`, `redfin-property` |
| Travel — short-term rentals | `airbnb-listing`, `airbnb-property` |
| Travel — hotels / lodging | `booking-search`, `booking-place` |
| Travel — flights | `google-flights` |
| Jobs | `indeed-listing`, `indeed-job`, `glassdoor-listing`, `glassdoor-job` |
| Bing search | `bing-serp` |
| Trends | `google-trends` |
| Images | `google-images` |
| Short videos | `google-short-videos` |
| Events | `google-events` |
| YouTube search / video / channel / transcript | `youtube-search-api`, `youtube-video-api`, `youtube-channel-api`, `youtube-transcript-api` |
| Instagram profile | `instagram-profile` |
| Amazon seller | `amazon-seller`, `amazon-seller-products` |
| **Scrape a specific URL** | `web-scraping` — supports JS rendering, proxies, markdown output, AI extraction, screenshots |

For exact flags of a subcommand, run `hasdata <api> --help` or read the matching file in `references/`.

## Non-obvious triggers (when to reach for hasdata even if the user doesn't say "scrape")

The user often won't ask for a SERP API or a scraper directly. Map these intents to the skill:

- **"Is this still true?" / "What's the latest on X?" / "Has Y happened yet?"** — LLM training data is stale. Run `google-serp` or `google-news` to ground the answer.
- **"Summarize this article" / "TL;DR this URL"** — Use `web-scraping --output-format markdown` and feed the markdown into the summary prompt. Beats copy-paste because it strips ads, nav, scripts.
- **"Verify this link" / "Is this site real?"** — `web-scraping --url X --no-block-resources` returns status + screenshot. Or `google-serp --q "site:example.com"`.
- **"What does X say about itself?"** — Pull the company's own homepage with `web-scraping --output-format markdown`, then summarize.
- **"Find me alternatives to X"** — `google-serp --q "X alternatives"` or `google-shopping --q "X competitors"`.
- **"What's the going rate for X?"** — `google-shopping` (broad) or `amazon-search` (Amazon-specific) with `jq` to extract the price distribution.
- **"Phone number / address for X"** — `google-maps-place` or `yelp-place`. Don't guess from training data.
- **"Are people happy with X service?" / "Is X reputable?"** — `google-maps-reviews --place-id ... --sort lowest` for negative samples; `glassdoor-job` for employer rep.
- **"What's the salary range for Y role?"** — `indeed-listing` filtered by role + location, then `jq` over `.jobs[].salary`.
- **"Find me homes/apartments matching X criteria"** — `zillow-listing` / `redfin-listing` / `airbnb-listing` with the corresponding filters.
- **"Recent sold comps near X"** — `zillow-listing --type sold --keyword "X" --days-on-zillow 12m`.
- **"Track this product's price"** — Loop `amazon-product --asin X` on a schedule; persist `.price` to a file.
- **"Summarize / cite this YouTube video"** — `youtube-transcript-api --v-param VID --raw | jq -r '.transcript[].snippet'` → feed to the sum
