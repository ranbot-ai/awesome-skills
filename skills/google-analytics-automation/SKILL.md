---
name: google-analytics-automation
description: Automate Google Analytics tasks via Rube MCP (Composio): run reports, list accounts/properties, funnels, pivots, key events. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/google-analytics-automation
---


# Google Analytics Automation via Rube MCP

Automate Google Analytics 4 (GA4) reporting and property management through Composio's Google Analytics toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Google Analytics connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `google_analytics`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `google_analytics`
3. If connection is not ACTIVE, follow the returned auth link to complete Google OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. List Accounts and Properties

**When to use**: User wants to discover available GA4 accounts and properties

**Tool sequence**:
1. `GOOGLE_ANALYTICS_LIST_ACCOUNTS` - List all accessible GA4 accounts [Required]
2. `GOOGLE_ANALYTICS_LIST_PROPERTIES` - List properties under an account [Required]

**Key parameters**:
- `pageSize`: Number of results per page
- `pageToken`: Pagination token from previous response
- `filter`: Filter expression for properties (e.g., `parent:accounts/12345`)

**Pitfalls**:
- Property IDs are numeric strings prefixed with 'properties/' (e.g., 'properties/123456')
- Account IDs are prefixed with 'accounts/' (e.g., 'accounts/12345')
- Always list accounts first, then properties under each account
- Pagination required for organizations with many properties

### 2. Run Standard Reports

**When to use**: User wants to query metrics and dimensions from GA4 data

**Tool sequence**:
1. `GOOGLE_ANALYTICS_LIST_PROPERTIES` - Get property ID [Prerequisite]
2. `GOOGLE_ANALYTICS_GET_METADATA` - Discover available dimensions and metrics [Optional]
3. `GOOGLE_ANALYTICS_CHECK_COMPATIBILITY` - Verify dimension/metric compatibility [Optional]
4. `GOOGLE_ANALYTICS_RUN_REPORT` - Execute the report query [Required]

**Key parameters**:
- `property`: Property ID (e.g., 'properties/123456')
- `dateRanges`: Array of date range objects with `startDate` and `endDate`
- `dimensions`: Array of dimension objects with `name` field
- `metrics`: Array of metric objects with `name` field
- `dimensionFilter` / `metricFilter`: Filter expressions
- `orderBys`: Sort order configuration
- `limit`: Maximum rows to return
- `offset`: Row offset for pagination

**Pitfalls**:
- Date format is 'YYYY-MM-DD' or relative values like 'today', 'yesterday', '7daysAgo', '30daysAgo'
- Not all dimensions and metrics are compatible; use CHECK_COMPATIBILITY first
- Use GET_METADATA to discover valid dimension and metric names
- Maximum 9 dimensions per report request
- Row limit defaults vary; set explicitly for large datasets
- `offset` is for result pagination, not date pagination

### 3. Run Batch Reports

**When to use**: User needs multiple different reports from the same property in one call

**Tool sequence**:
1. `GOOGLE_ANALYTICS_LIST_PROPERTIES` - Get property ID [Prerequisite]
2. `GOOGLE_ANALYTICS_BATCH_RUN_REPORTS` - Execute multiple reports at once [Required]

**Key parameters**:
- `property`: Property ID (required)
- `requests`: Array of individual report request objects (same structure as RUN_REPORT)

**Pitfalls**:
- Maximum 5 report requests per batch call
- All reports in a batch must target the same property
- Each individual report has the same dimension/metric limits as RUN_REPORT
- Batch errors may affect all reports; check individual report responses

### 4. Run Pivot Reports

**When to use**: User wants cross-tabulated data (rows vs columns) like pivot tables

**Tool sequence**:
1. `GOOGLE_ANALYTICS_LIST_PROPERTIES` - Get property ID [Prerequisite]
2. `GOOGLE_ANALYTICS_RUN_PIVOT_REPORT` - Execute pivot report [Required]

**Key parameters**:
- `property`: Property ID (required)
- `dateRanges`: Date range objects
- `dimensions`: All dimensions used in any pivot
- `metrics`: Metrics to aggregate
- `pivots`: Array of pivot definitions with `fieldNames`, `limit`, and `orderBys`

**Pitfalls**:
- Dimensions used in pivots must also be listed in top-level `dimensions`
- Pivot `fieldNames` reference dimension names from the top-level list
- Complex pivots with many dimensions can produce very large result sets
- Each pivot has its own independent `limit` and `orderBys`

### 5. Run Funnel Reports

**When to use**: User wants to analyze conversion funnels and drop-off rates

**Tool sequence**:
1. `GOOGLE_ANALYTICS_LIST_PROPERTIES` - Get property ID [Prerequisite]
2. `GOOGLE_ANALYTICS_RUN_FUNNEL_REPORT` - Execute funnel analysis [Required]

**Key parameters**:
- `property`: Property ID (required)
- `dateRanges`: Date range objects
- `funnel`: Funnel definition with `steps` array
- `funnelBreakdown`: Optional dimension to break down funnel b
