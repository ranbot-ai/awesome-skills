---
name: apify-youtube-transcript-scraper
description: Get YouTube captions, timestamped quotations, SRT/VTT and translated transcripts for videos, channels and playlists through the harshmaur/youtube-transcript-scraper Apify Actor. 
category: Development & Code Tools
source: antigravity
tags: [api, mcp, claude, ai, agent, workflow, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-youtube-transcript-scraper
---


# YouTube Transcript Scraper

Turn a YouTube link, a channel or a playlist into text with one run of `harshmaur/youtube-transcript-scraper`. Each video gives one row with the transcript and the video facts. The agent picks the input list, sets how many videos to read per channel, and chooses the transcript shape.

Disclosure: the Actor is paid per result and is built by the skill author. Links carry no affiliate parameters.

## When to Use

Use to summarize public YouTube videos, find timestamped quotations, export captions, or research transcripts from channels and playlists.

## Example prompts

Prompts this skill handles:

- "Summarize https://youtu.be/jNQXAC9IVRw in five bullet points."
- "Give me SRT subtitles for these three videos."
- "Pull the transcripts of the last 20 videos from @mkbhd and list every product he reviewed."
- "Transcripts of this playlist, in Spanish, with timestamps so I can link to the exact second."

Out of scope (the boundary):

- "Download the MP4" or "get the audio" — this Actor returns text and metadata only.
- "Find videos about X" — it does not search YouTube. Get the video, channel or playlist links first.
- "Read the comments" — use a YouTube comments Actor.

## Prerequisites

- Apify account ([sign up](https://apify.com)). The free plan's monthly credit pays for about 1,000 transcripts.
- Authentication via one of:
  - `apify login` (OAuth, if you use the Apify CLI)
  - `APIFY_TOKEN` environment variable
  - Token from [Apify Console → Settings → Integrations](https://console.apify.com/settings/integrations)
- A previously installed and reviewed Apify CLI, or the Apify MCP server (see "Calling the Actor").

## Workflow

### Step 1 — Pick the input list

| The user gives you | Field | Notes |
|---|---|---|
| Video links: `watch?v=`, `youtu.be/`, `/shorts/`, `/live/` | `videoUrls` | One row per link. `maxVideos` does not apply. |
| A channel: `@handle`, `youtube.com/@handle`, `/channel/UC…`, `/c/Name` | `channelUrls` | The newest uploads, up to `maxVideos` per channel. |
| A playlist: `youtube.com/playlist?list=…` | `playlistUrls` | Playlist order, up to `maxVideos`; about 100 at most. |

Mix the three lists in one run when the user names videos and channels together.

### Step 2 — Set the options

| Field | Values | Default |
|---|---|---|
| `maxVideos` | Videos per channel or playlist | 50 |
| `dateFrom`, `dateTo` | `YYYY-MM-DD`, publish date window | none |
| `language` | ISO 639-1 code (`en`, `es`, `hi`, `ja`) | the video's own caption language |
| `transcriptFormat` | `both`, `segments`, `text`, `srt`, `vtt` | `both` |

Pick the format from the task:

- Summary, Q&A, RAG chunks → `text` (smallest rows).
- Quotes with a link to the exact second → `segments` or `both`.
- A subtitle file for an editor or player → `srt` or `vtt`.

Example input:

```json
{
  "channelUrls": ["@mkbhd"],
  "maxVideos": 20,
  "dateFrom": "2026-09-01",
  "transcriptFormat": "text"
}
```

Fetch the live schema when a field is in doubt:

```bash
apify actors info "harshmaur/youtube-transcript-scraper" --input --json \
  --user-agent apify-awesome-skills/apify-youtube-transcript-scraper 2>/dev/null
```

### Step 3 — Estimate the cost, then run

You pay only for transcripts in the dataset. Videos with no captions, private videos and videos outside the date window cost nothing.

| Apify plan | Per 1,000 transcripts |
|---|---|
| Free | $5.00 |
| Starter | $4.67 |
| Scale | $4.33 |
| Business and higher | $4.00 |

`cost ≈ videos × $0.005`. For channels, videos = channels × `maxVideos`. The $1/200-video example is not spending authorization. Verify current Actor pricing and obtain approval for the actual input, maximum results and budget, unless existing explicit authorization already covers that scope.

```bash
apify actors call "harshmaur/youtube-transcript-scraper" \
  -i '{"videoUrls":["https://youtu.be/jNQXAC9IVRw"],"transcriptFormat":"text"}' \
  --json \
  --user-agent apify-awesome-skills/apify-youtube-transcript-scraper \
  2>/dev/null
```

The output gives `status` and the dataset ID at `storage.defaultDatasetId`. A measured run of 4 transcripts (2 links and 2 channel videos) finished in under a minute. A run of several hundred videos can take many minutes. Start long runs without waiting and poll with `apify runs info "RUN_ID" --json --user-agent apify-awesome-skills/apify-youtube-transcript-scraper 2>/dev/null`.

### Step 4 — Fetch and report

```bash
EXPORT_DIR="$(mktemp -d)" || exit 1
apify datasets get-items "DATASET_ID" --format json \
  --user-agent apify-awesome-skills/apify-youtube-transcript-scraper \
  2>/dev/null > "$EXPORT_DIR/yt-transcripts.json"
```

Each row has `dataType`: `transcript` or `failed`.

| Need | Fields |
|---|---|
| Video | `videoId`, `url`, `title`, `description`, `durationSeconds`, `publishedAt`, `category`, `keywords`, `thumbnail` |
| Numbers | `viewCount`, `likeCount`, `commentCount` |
| Channel | `channelName`, `channelId`, `channelUrl`, `channelUsername
