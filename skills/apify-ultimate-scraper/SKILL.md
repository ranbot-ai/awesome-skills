---
name: apify-ultimate-scraper
description: Select a candidate Apify Actor for the requested extraction after checking its current schema, provenance, pricing and limits. The Actor table is a historical shortlist, not a verified availability or
category: Document Processing
source: antigravity
tags: [react, node, api, mcp, ai, workflow, spreadsheet, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-ultimate-scraper
---


# Universal Web Scraper

Select a candidate Apify Actor for the requested extraction after checking its current schema, provenance, pricing and limits. The Actor table is a historical shortlist, not a verified availability or best-choice guarantee.

## When to Use
- The user needs web data extraction but has not yet chosen a specific Apify Actor.
- You need a general-purpose Apify entry point that maps a broad scraping goal to the most suitable Actor.
- The task spans multiple platforms and benefits from one unified workflow for actor selection, execution, and summarization.

## Prerequisites
Verify prerequisites before execution without printing credentials.

- `.env` file with `APIFY_TOKEN`
- A supported Node.js release with native fetch, --env-file and ES module syntax detection, or an explicitly configured module package scope
- `mcpc` CLI tool: `npm install -g @apify/mcpc`

## Workflow

Copy this checklist and track progress:

```
Task Progress:
- [ ] Step 1: Understand user goal and select Actor
- [ ] Step 2: Fetch Actor schema via mcpc
- [ ] Step 3: Ask user preferences (format, filename)
- [ ] Step 4: Run the scraper script
- [ ] Step 5: Summarize results and offer follow-ups
```

### Step 1: Understand User Goal and Select Actor

First, understand what the user wants to achieve. Then select the best Actor from the options below.

#### Instagram Actors (12)

| Actor ID | Best For |
|----------|----------|
| `apify/instagram-profile-scraper` | Profile data, follower counts, bio info |
| `apify/instagram-post-scraper` | Individual post details, engagement metrics |
| `apify/instagram-comment-scraper` | Comment extraction, sentiment analysis |
| `apify/instagram-hashtag-scraper` | Hashtag content, trending topics |
| `apify/instagram-hashtag-stats` | Hashtag performance metrics |
| `apify/instagram-reel-scraper` | Reels content and metrics |
| `apify/instagram-search-scraper` | Search users, places, hashtags |
| `apify/instagram-tagged-scraper` | Posts tagged with specific accounts |
| `apify/instagram-followers-count-scraper` | Follower count tracking |
| `apify/instagram-scraper` | Comprehensive Instagram data |
| `apify/instagram-api-scraper` | API-based Instagram access |
| `apify/export-instagram-comments-posts` | Bulk comment/post export |

#### Facebook Actors (14)

| Actor ID | Best For |
|----------|----------|
| `apify/facebook-pages-scraper` | Page data, metrics, contact info |
| `apify/facebook-page-contact-information` | Emails, phones, addresses from pages |
| `apify/facebook-posts-scraper` | Post content and engagement |
| `apify/facebook-comments-scraper` | Comment extraction |
| `apify/facebook-likes-scraper` | Reaction analysis |
| `apify/facebook-reviews-scraper` | Page reviews |
| `apify/facebook-groups-scraper` | Group content and members |
| `apify/facebook-events-scraper` | Event data |
| `apify/facebook-ads-scraper` | Ad creative and targeting |
| `apify/facebook-search-scraper` | Search results |
| `apify/facebook-reels-scraper` | Reels content |
| `apify/facebook-photos-scraper` | Photo extraction |
| `apify/facebook-marketplace-scraper` | Marketplace listings |
| `apify/facebook-followers-following-scraper` | Follower/following lists |

#### TikTok Actors (14)

| Actor ID | Best For |
|----------|----------|
| `clockworks/tiktok-scraper` | Comprehensive TikTok data |
| `clockworks/free-tiktok-scraper` | Free TikTok extraction |
| `clockworks/tiktok-profile-scraper` | Profile data |
| `clockworks/tiktok-video-scraper` | Video details and metrics |
| `clockworks/tiktok-comments-scraper` | Comment extraction |
| `clockworks/tiktok-followers-scraper` | Follower lists |
| `clockworks/tiktok-user-search-scraper` | Find users by keywords |
| `clockworks/tiktok-hashtag-scraper` | Hashtag content |
| `clockworks/tiktok-sound-scraper` | Trending sounds |
| `clockworks/tiktok-ads-scraper` | Ad content |
| `clockworks/tiktok-discover-scraper` | Discover page content |
| `clockworks/tiktok-explore-scraper` | Explore content |
| `clockworks/tiktok-trends-scraper` | Trending content |
| `clockworks/tiktok-live-scraper` | Live stream data |

#### YouTube Actors (5)

| Actor ID | Best For |
|----------|----------|
| `streamers/youtube-scraper` | Video data and metrics |
| `streamers/youtube-channel-scraper` | Channel information |
| `streamers/youtube-comments-scraper` | Comment extraction |
| `streamers/youtube-shorts-scraper` | Shorts content |
| `streamers/youtube-video-scraper-by-hashtag` | Videos by hashtag |

#### Google Maps Actors (4)

| Actor ID | Best For |
|----------|----------|
| `compass/crawler-google-places` | Business listings, ratings, contact info |
| `compass/google-maps-extractor` | Detailed business data |
| `compass/Google-Maps-Reviews-Scraper` | Review extraction |
| `poidata/google-maps-email-extractor` | Email discovery from listings |

#### X/Twitter Actors (2)

| Actor ID | Best For |
|----------|----------|
| [`xquik/x-tweet-scraper`](https://apify.com/xquik/x-tw
