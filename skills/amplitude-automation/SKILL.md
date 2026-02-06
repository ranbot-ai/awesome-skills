---
name: amplitude-automation
description: Automate Amplitude tasks via Rube MCP (Composio): events, user activity, cohorts, user identification. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, git, json, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/amplitude-automation
---


# Amplitude Automation via Rube MCP

Automate Amplitude product analytics through Composio's Amplitude toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Amplitude connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `amplitude`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `amplitude`
3. If connection is not ACTIVE, follow the returned auth link to complete Amplitude authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Send Events

**When to use**: User wants to track events or send event data to Amplitude

**Tool sequence**:
1. `AMPLITUDE_SEND_EVENTS` - Send one or more events to Amplitude [Required]

**Key parameters**:
- `events`: Array of event objects, each containing:
  - `event_type`: Name of the event (e.g., 'page_view', 'purchase')
  - `user_id`: Unique user identifier (required if no `device_id`)
  - `device_id`: Device identifier (required if no `user_id`)
  - `event_properties`: Object with custom event properties
  - `user_properties`: Object with user properties to set
  - `time`: Event timestamp in milliseconds since epoch

**Pitfalls**:
- At least one of `user_id` or `device_id` is required per event
- `event_type` is required for every event; cannot be empty
- `time` must be in milliseconds (13-digit epoch), not seconds
- Batch limit applies; check schema for maximum events per request
- Events are processed asynchronously; successful API response does not mean data is immediately queryable

### 2. Get User Activity

**When to use**: User wants to view event history for a specific user

**Tool sequence**:
1. `AMPLITUDE_FIND_USER` - Find user by ID or property [Prerequisite]
2. `AMPLITUDE_GET_USER_ACTIVITY` - Retrieve user's event stream [Required]

**Key parameters**:
- `user`: Amplitude internal user ID (from FIND_USER)
- `offset`: Pagination offset for event list
- `limit`: Maximum number of events to return

**Pitfalls**:
- `user` parameter requires Amplitude's internal user ID, NOT your application's user_id
- Must call FIND_USER first to resolve your user_id to Amplitude's internal ID
- Activity is returned in reverse chronological order by default
- Large activity histories require pagination via `offset`

### 3. Find and Identify Users

**When to use**: User wants to look up users or set user properties

**Tool sequence**:
1. `AMPLITUDE_FIND_USER` - Search for a user by various identifiers [Required]
2. `AMPLITUDE_IDENTIFY` - Set or update user properties [Optional]

**Key parameters**:
- For FIND_USER:
  - `user`: Search term (user_id, email, or Amplitude ID)
- For IDENTIFY:
  - `user_id`: Your application's user identifier
  - `device_id`: Device identifier (alternative to user_id)
  - `user_properties`: Object with `$set`, `$unset`, `$add`, `$append` operations

**Pitfalls**:
- FIND_USER searches across user_id, device_id, and Amplitude ID
- IDENTIFY uses special property operations (`$set`, `$unset`, `$add`, `$append`)
- `$set` overwrites existing values; `$setOnce` only sets if not already set
- At least one of `user_id` or `device_id` is required for IDENTIFY
- User property changes are eventually consistent; not immediate

### 4. Manage Cohorts

**When to use**: User wants to list cohorts, view cohort details, or update cohort membership

**Tool sequence**:
1. `AMPLITUDE_LIST_COHORTS` - List all saved cohorts [Required]
2. `AMPLITUDE_GET_COHORT` - Get detailed cohort information [Optional]
3. `AMPLITUDE_UPDATE_COHORT_MEMBERSHIP` - Add/remove users from a cohort [Optional]
4. `AMPLITUDE_CHECK_COHORT_STATUS` - Check async cohort operation status [Optional]

**Key parameters**:
- For LIST_COHORTS: No required parameters
- For GET_COHORT: `cohort_id` (from list results)
- For UPDATE_COHORT_MEMBERSHIP:
  - `cohort_id`: Target cohort ID
  - `memberships`: Object with `add` and/or `remove` arrays of user IDs
- For CHECK_COHORT_STATUS: `request_id` from update response

**Pitfalls**:
- Cohort IDs are required for all cohort-specific operations
- UPDATE_COHORT_MEMBERSHIP is asynchronous; use CHECK_COHORT_STATUS to verify
- `request_id` from the update response is needed for status checking
- Maximum membership changes per request may be limited; chunk large updates
- Only behavioral cohorts support API membership updates

### 5. Browse Event Categories

**When to use**: User wants to discover available event types and categories in Amplitude

**Tool sequence**:
1. `AMPLITUDE_GET_EVENT_CATEGORIES` - List all event categories [Required]

**Key parameters**:
- No required parameters; returns all configured event categories

**Pitfalls**:
- Categories are configured in A
