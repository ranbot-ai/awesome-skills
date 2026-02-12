---
name: outlook-calendar-automation
description: Automate Outlook Calendar tasks via Rube MCP (Composio): create events, manage attendees, find meeting times, and handle invitations. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/outlook-calendar-automation
---


# Outlook Calendar Automation via Rube MCP

Automate Outlook Calendar operations through Composio's Outlook toolkit via Rube MCP.

**Toolkit docs**: [composio.dev/toolkits/outlook](https://composio.dev/toolkits/outlook)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Outlook connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `outlook`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `outlook`
3. If connection is not ACTIVE, follow the returned auth link to complete Microsoft OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create Calendar Events

**When to use**: User wants to schedule a new event on their Outlook calendar

**Tool sequence**:
1. `OUTLOOK_LIST_CALENDARS` - List available calendars [Optional]
2. `OUTLOOK_CALENDAR_CREATE_EVENT` - Create the event [Required]

**Key parameters**:
- `subject`: Event title
- `start_datetime`: ISO 8601 start time (e.g., '2025-01-03T10:00:00')
- `end_datetime`: ISO 8601 end time (must be after start)
- `time_zone`: IANA or Windows timezone (e.g., 'America/New_York', 'Pacific Standard Time')
- `attendees_info`: Array of email strings or attendee objects
- `body`: Event description (plain text or HTML)
- `is_html`: Set true if body contains HTML
- `location`: Physical location string
- `is_online_meeting`: Set true for Teams meeting link
- `online_meeting_provider`: 'teamsForBusiness' for Teams integration
- `show_as`: 'free', 'tentative', 'busy', 'oof'

**Pitfalls**:
- start_datetime must be chronologically before end_datetime
- time_zone is required and must be a valid IANA or Windows timezone name
- Adding attendees can trigger invitation emails immediately
- To generate a Teams meeting link, set BOTH is_online_meeting=true AND online_meeting_provider='teamsForBusiness'
- user_id defaults to 'me'; use email or UUID for other users' calendars

### 2. List and Search Events

**When to use**: User wants to find events on their calendar

**Tool sequence**:
1. `OUTLOOK_GET_MAILBOX_SETTINGS` - Get user timezone for accurate queries [Prerequisite]
2. `OUTLOOK_LIST_EVENTS` - Search events with filters [Required]
3. `OUTLOOK_GET_EVENT` - Get full details for a specific event [Optional]
4. `OUTLOOK_GET_CALENDAR_VIEW` - Get events active during a time window [Alternative]

**Key parameters**:
- `filter`: OData filter string (e.g., "start/dateTime ge '2024-07-01T00:00:00Z'")
- `select`: Array of properties to return
- `orderby`: Sort criteria (e.g., ['start/dateTime desc'])
- `top`: Results per page (1-999)
- `timezone`: Display timezone for results
- `start_datetime`/`end_datetime`: For CALENDAR_VIEW time window (UTC with Z suffix)

**Pitfalls**:
- OData filter datetime values require single quotes and Z suffix
- Use 'start/dateTime' for event start filtering, NOT 'receivedDateTime' (that is for emails)
- 'createdDateTime' supports orderby/select but NOT filtering
- Pagination: follow @odata.nextLink until all pages are collected
- CALENDAR_VIEW is better for "what's on my calendar today" queries (includes spanning events)
- LIST_EVENTS is better for keyword/category filtering
- Response events have start/end nested as start.dateTime and end.dateTime

### 3. Update Events

**When to use**: User wants to modify an existing calendar event

**Tool sequence**:
1. `OUTLOOK_LIST_EVENTS` - Find the event to update [Prerequisite]
2. `OUTLOOK_UPDATE_CALENDAR_EVENT` - Update the event [Required]

**Key parameters**:
- `event_id`: Unique event identifier (from LIST_EVENTS)
- `subject`: New event title (optional)
- `start_datetime`/`end_datetime`: New times (optional)
- `time_zone`: Timezone for new times
- `attendees`: Updated attendee list (replaces existing if provided)
- `body`: Updated description with contentType and content
- `location`: Updated location

**Pitfalls**:
- UPDATE merges provided fields with existing event; unspecified fields are preserved
- Providing attendees replaces the ENTIRE attendee list; include all desired attendees
- Providing categories replaces the ENTIRE category list
- Updating times may trigger re-sends to attendees
- event_id is required; obtain from LIST_EVENTS first

### 4. Delete Events and Decline Invitations

**When to use**: User wants to remove an event or decline a meeting invitation

**Tool sequence**:
1. `OUTLOOK_DELETE_EVENT` - Delete an event [Optional]
2. `OUTLOOK_DECLINE_EVENT` - Decline a meeting invitation [Optional]

**Key parameters**:
- `event_id`: Event to delete or decline
- `send_notifications`: Send cancellation notices to attendees (default true)
- `comment`: Reason for declining (for DECLINE_EVENT)
- `proposedNewTime`: Suggest altern
