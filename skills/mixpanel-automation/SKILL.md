---
name: mixpanel-automation
description: Automate Mixpanel tasks via Rube MCP (Composio): events, segmentation, funnels, cohorts, user profiles, JQL queries. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [javascript, api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/mixpanel-automation
---


# Mixpanel Automation via Rube MCP

Automate Mixpanel product analytics through Composio's Mixpanel toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Mixpanel connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `mixpanel`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `mixpanel`
3. If connection is not ACTIVE, follow the returned auth link to complete Mixpanel authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Aggregate Event Data

**When to use**: User wants to count events, get totals, or track event trends over time

**Tool sequence**:
1. `MIXPANEL_GET_ALL_PROJECTS` - List projects to get project ID [Prerequisite]
2. `MIXPANEL_AGGREGATE_EVENT_COUNTS` - Get event counts and aggregations [Required]

**Key parameters**:
- `event`: Event name or array of event names to aggregate
- `from_date` / `to_date`: Date range in 'YYYY-MM-DD' format
- `unit`: Time granularity ('minute', 'hour', 'day', 'week', 'month')
- `type`: Aggregation type ('general', 'unique', 'average')
- `where`: Filter expression for event properties

**Pitfalls**:
- Date format must be 'YYYY-MM-DD'; other formats cause errors
- Event names are case-sensitive; use exact names from your Mixpanel project
- `where` filter uses Mixpanel expression syntax (e.g., `properties["country"] == "US"`)
- Maximum date range may be limited depending on your Mixpanel plan

### 2. Run Segmentation Queries

**When to use**: User wants to break down events by properties for detailed analysis

**Tool sequence**:
1. `MIXPANEL_QUERY_SEGMENTATION` - Run segmentation analysis [Required]

**Key parameters**:
- `event`: Event name to segment
- `from_date` / `to_date`: Date range in 'YYYY-MM-DD' format
- `on`: Property to segment by (e.g., `properties["country"]`)
- `unit`: Time granularity
- `type`: Count type ('general', 'unique', 'average')
- `where`: Filter expression
- `limit`: Maximum number of segments to return

**Pitfalls**:
- The `on` parameter uses Mixpanel property expression syntax
- Property references must use `properties["prop_name"]` format
- Segmentation on high-cardinality properties returns capped results; use `limit`
- Results are grouped by the segmentation property and time unit

### 3. Analyze Funnels

**When to use**: User wants to track conversion funnels and identify drop-off points

**Tool sequence**:
1. `MIXPANEL_LIST_FUNNELS` - List saved funnels to find funnel ID [Prerequisite]
2. `MIXPANEL_QUERY_FUNNEL` - Execute funnel analysis [Required]

**Key parameters**:
- `funnel_id`: ID of the saved funnel to query
- `from_date` / `to_date`: Date range
- `unit`: Time granularity
- `where`: Filter expression
- `on`: Property to segment funnel by
- `length`: Conversion window in days

**Pitfalls**:
- `funnel_id` is required; resolve via LIST_FUNNELS first
- Funnels must be created in Mixpanel UI first; API only queries existing funnels
- Conversion window (`length`) defaults vary; set explicitly for accuracy
- Large date ranges with segmentation can produce very large responses

### 4. Manage User Profiles

**When to use**: User wants to query or update user profiles in Mixpanel

**Tool sequence**:
1. `MIXPANEL_QUERY_PROFILES` - Search and filter user profiles [Required]
2. `MIXPANEL_PROFILE_BATCH_UPDATE` - Update multiple user profiles [Optional]

**Key parameters**:
- `where`: Filter expression for profile properties (e.g., `properties["plan"] == "premium"`)
- `output_properties`: Array of property names to include in results
- `page`: Page number for pagination
- `session_id`: Session ID for consistent pagination (from first response)
- For batch update: array of profile updates with `$distinct_id` and property operations

**Pitfalls**:
- Profile queries return paginated results; use `session_id` from first response for consistent paging
- `where` uses Mixpanel expression syntax for profile properties
- BATCH_UPDATE applies operations (`$set`, `$unset`, `$add`, `$append`) to profiles
- Batch update has a maximum number of profiles per request; chunk larger updates
- Profile property names are case-sensitive

### 5. Manage Cohorts

**When to use**: User wants to list or analyze user cohorts

**Tool sequence**:
1. `MIXPANEL_COHORTS_LIST` - List all saved cohorts [Required]

**Key parameters**:
- No required parameters; returns all accessible cohorts
- Response includes cohort `id`, `name`, `description`, `count`

**Pitfalls**:
- Cohorts are created and managed in Mixpanel UI; API provides read access
- Cohort IDs are numeric; use exact ID from list results
- Cohort counts may be approximate for very large cohorts
- Cohorts can 
