---
name: zoom-automation
description: Automate Zoom meeting creation, management, recordings, webinars, and participant tracking via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, git, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/zoom-automation
---


# Zoom Automation via Rube MCP

Automate Zoom operations including meeting scheduling, webinar management, cloud recording retrieval, participant tracking, and usage reporting through Composio's Zoom toolkit.

**Toolkit docs**: [composio.dev/toolkits/zoom](https://composio.dev/toolkits/zoom)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Zoom connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `zoom`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas
- Most features require a paid Zoom account (Pro plan or higher)

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `zoom`
3. If connection is not ACTIVE, follow the returned auth link to complete Zoom OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Schedule Meetings

**When to use**: User wants to create a new Zoom meeting with specific time, duration, and settings

**Tool sequence**:
1. `ZOOM_GET_USER` - Verify authenticated user and check license type [Prerequisite]
2. `ZOOM_CREATE_A_MEETING` - Create the meeting with topic, time, duration, and settings [Required]
3. `ZOOM_GET_A_MEETING` - Retrieve full meeting details including join_url [Optional]
4. `ZOOM_UPDATE_A_MEETING` - Modify meeting settings or reschedule [Optional]
5. `ZOOM_ADD_A_MEETING_REGISTRANT` - Register participants for registration-enabled meetings [Optional]

**Key parameters**:
- `userId`: Always use `"me"` for user-level apps
- `topic`: Meeting subject line
- `type`: `1` (instant), `2` (scheduled), `3` (recurring no fixed time), `8` (recurring fixed time)
- `start_time`: ISO 8601 format (`yyyy-MM-ddTHH:mm:ssZ` for UTC or `yyyy-MM-ddTHH:mm:ss` with timezone field)
- `timezone`: Timezone ID (e.g., `"America/New_York"`)
- `duration`: Duration in minutes
- `settings__auto_recording`: `"none"`, `"local"`, or `"cloud"`
- `settings__waiting_room`: Boolean to enable waiting room
- `settings__join_before_host`: Boolean (disabled when waiting room is enabled)
- `settings__meeting_invitees`: Array of invitee objects with email addresses

**Pitfalls**:
- `start_time` must be in the future; Zoom stores and returns times in UTC regardless of input timezone
- If no `start_time` is set for type `2`, it becomes an instant meeting that expires after 30 days
- The `join_url` for participants and `start_url` for host come from the create response - persist these
- `start_url` expires in 2 hours (or 90 days for `custCreate` users)
- Meeting creation is rate-limited to 100 requests/day
- Setting names use double underscores for nesting (e.g., `settings__host_video`)

### 2. List and Manage Meetings

**When to use**: User wants to view upcoming, live, or past meetings

**Tool sequence**:
1. `ZOOM_LIST_MEETINGS` - List meetings by type (scheduled, live, upcoming, previous) [Required]
2. `ZOOM_GET_A_MEETING` - Get detailed info for a specific meeting [Optional]
3. `ZOOM_UPDATE_A_MEETING` - Modify meeting details [Optional]

**Key parameters**:
- `userId`: Use `"me"` for authenticated user
- `type`: `"scheduled"` (default), `"live"`, `"upcoming"`, `"upcoming_meetings"`, `"previous_meetings"`
- `page_size`: Records per page (default 30)
- `next_page_token`: Pagination token from previous response
- `from` / `to`: Date range filters

**Pitfalls**:
- `ZOOM_LIST_MEETINGS` excludes instant meetings and only shows unexpired scheduled meetings
- For past meetings, use `type: "previous_meetings"`
- Pagination: always follow `next_page_token` until empty to get complete results
- Token expiration: `next_page_token` expires after 15 minutes
- Meeting IDs can exceed 10 digits; store as long integers, not standard integers

### 3. Manage Recordings

**When to use**: User wants to list, retrieve, or delete cloud recordings

**Tool sequence**:
1. `ZOOM_LIST_ALL_RECORDINGS` - List all cloud recordings for a user within a date range [Required]
2. `ZOOM_GET_MEETING_RECORDINGS` - Get recordings for a specific meeting [Optional]
3. `ZOOM_DELETE_MEETING_RECORDINGS` - Move recordings to trash or permanently delete [Optional]
4. `ZOOM_LIST_ARCHIVED_FILES` - List archived meeting/webinar files [Optional]

**Key parameters**:
- `userId`: Use `"me"` for authenticated user
- `from` / `to`: Date range in `yyyy-mm-dd` format (max 1 month range)
- `meetingId`: Meeting ID or UUID for specific recording retrieval
- `action`: `"trash"` (recoverable) or `"delete"` (permanent) for deletion
- `include_fields`: Set to `"download_access_token"` to get JWT for downloading recordings
- `trash`: Set `true` to list recordings from trash

**Pitfalls**:
- Date range maximum is 1 month; API auto-adjusts `from` if range exceeds this
- Cloud Recording must be enabled on the account
- UUIDs starting with `
