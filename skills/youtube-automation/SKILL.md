---
name: youtube-automation
description: Automate YouTube tasks via Rube MCP (Composio): upload videos, manage playlists, search content, get analytics, and handle comments. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/youtube-automation
---


# YouTube Automation via Rube MCP

Automate YouTube operations through Composio's YouTube toolkit via Rube MCP.

**Toolkit docs**: [composio.dev/toolkits/youtube](https://composio.dev/toolkits/youtube)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active YouTube connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `youtube`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `youtube`
3. If connection is not ACTIVE, follow the returned auth link to complete Google OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Upload and Manage Videos

**When to use**: User wants to upload a video or update video metadata

**Tool sequence**:
1. `YOUTUBE_UPLOAD_VIDEO` - Upload a new video [Required]
2. `YOUTUBE_UPDATE_VIDEO` - Update title, description, tags, privacy [Optional]
3. `YOUTUBE_UPDATE_THUMBNAIL` - Set a custom thumbnail [Optional]

**Key parameters**:
- `title`: Video title (max 100 characters)
- `description`: Video description (max 5000 bytes)
- `tags`: Array of keyword tags
- `categoryId`: YouTube category ID (e.g., '22' for People & Blogs)
- `privacyStatus`: 'public', 'private', or 'unlisted'
- `videoFilePath`: Object with `{name, mimetype, s3key}` for the video file

**Pitfalls**:
- UPLOAD_VIDEO consumes high quota; prefer UPDATE_VIDEO for metadata-only changes
- videoFilePath must be an object with s3key, not a raw file path or URL
- Tags total must not exceed 500 characters including separators
- Angle brackets `< >` in tags are automatically stripped
- Description limit is 5000 bytes, not characters (multibyte chars count more)

### 2. Search YouTube Content

**When to use**: User wants to find videos, channels, or playlists

**Tool sequence**:
1. `YOUTUBE_SEARCH_YOU_TUBE` - Search for content [Required]
2. `YOUTUBE_VIDEO_DETAILS` - Get full details for a specific video [Optional]
3. `YOUTUBE_GET_VIDEO_DETAILS_BATCH` - Get details for multiple videos [Optional]

**Key parameters**:
- `q`: Search query (supports exact phrases, exclusions, channel handles)
- `type`: 'video', 'channel', or 'playlist'
- `maxResults`: Results per page (1-50)
- `pageToken`: For pagination

**Pitfalls**:
- Search endpoint only returns 'snippet' part; use VIDEO_DETAILS for statistics
- Search results are capped at 500 total items
- Search has higher quota cost (100 units) vs list endpoints (1 unit)
- BATCH video details practical limit is ~50 IDs per call; chunk larger sets

### 3. Manage Playlists

**When to use**: User wants to create playlists or manage playlist contents

**Tool sequence**:
1. `YOUTUBE_LIST_USER_PLAYLISTS` - List user's existing playlists [Optional]
2. `YOUTUBE_CREATE_PLAYLIST` - Create a new playlist [Optional]
3. `YOUTUBE_ADD_VIDEO_TO_PLAYLIST` - Add a video to a playlist [Optional]
4. `YOUTUBE_LIST_PLAYLIST_ITEMS` - List videos in a playlist [Optional]

**Key parameters**:
- `playlistId`: Playlist ID ('PL...' for user-created, 'UU...' for uploads)
- `part`: Resource parts to include (e.g., 'snippet,contentDetails')
- `maxResults`: Items per page (1-50)
- `pageToken`: Pagination token from previous response

**Pitfalls**:
- Do NOT pass channel IDs ('UC...') as playlist IDs; convert 'UC' to 'UU' for uploads
- Large playlists require pagination via pageToken; follow nextPageToken until absent
- items[].id is not the videoId; use items[].snippet.resourceId.videoId
- Creating duplicate playlist names is allowed; check existing playlists first

### 4. Get Channel and Video Analytics

**When to use**: User wants to analyze channel performance or video metrics

**Tool sequence**:
1. `YOUTUBE_GET_CHANNEL_ID_BY_HANDLE` - Resolve a handle to channel ID [Prerequisite]
2. `YOUTUBE_GET_CHANNEL_STATISTICS` - Get channel subscriber/view/video counts [Required]
3. `YOUTUBE_LIST_CHANNEL_VIDEOS` - List all videos from a channel [Optional]
4. `YOUTUBE_GET_VIDEO_DETAILS_BATCH` - Get per-video statistics [Optional]
5. `YOUTUBE_GET_CHANNEL_ACTIVITIES` - Get recent channel activities [Optional]

**Key parameters**:
- `channelId`: Channel ID ('UC...'), handle ('@handle'), or 'me'
- `forHandle`: Channel handle (e.g., '@Google')
- `id`: Comma-separated video IDs for batch details
- `parts`: Resource parts to include (e.g., 'snippet,statistics')

**Pitfalls**:
- Channel statistics are lifetime totals, not per-period
- BATCH video details may return fewer items than requested for private/deleted videos
- Response data may be nested under `data` or `data_preview`; parse defensively
- contentDetails.duration uses ISO 8601 format (e.g., 'PT4M13S')

### 5. Manage Subscriptions and Comments

**When to use**: User wants to subscribe to channels or view vid
