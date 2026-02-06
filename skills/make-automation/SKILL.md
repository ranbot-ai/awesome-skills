---
name: make-automation
description: Automate Make (Integromat) tasks via Rube MCP (Composio): operations, enums, language and timezone lookups. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/make-automation
---


# Make Automation via Rube MCP

Automate Make (formerly Integromat) operations through Composio's Make toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Make connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `make`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `make`
3. If connection is not ACTIVE, follow the returned auth link to complete Make authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Get Operations Data

**When to use**: User wants to retrieve operation logs or usage data from Make scenarios

**Tool sequence**:
1. `MAKE_GET_OPERATIONS` - Retrieve operation records [Required]

**Key parameters**:
- Check current schema via RUBE_SEARCH_TOOLS for available filters
- May include date range, scenario ID, or status filters

**Pitfalls**:
- Operations data may be paginated; check for pagination tokens
- Date filters must match expected format from schema
- Large result sets should be filtered by date range or scenario

### 2. List Available Languages

**When to use**: User wants to see supported languages for Make scenarios or interfaces

**Tool sequence**:
1. `MAKE_LIST_ENUMS_LANGUAGES` - Get all supported language codes [Required]

**Key parameters**:
- No required parameters; returns complete language list

**Pitfalls**:
- Language codes follow standard locale format (e.g., 'en', 'fr', 'de')
- List is static and rarely changes; cache results when possible

### 3. List Available Timezones

**When to use**: User wants to see supported timezones for scheduling Make scenarios

**Tool sequence**:
1. `MAKE_LIST_ENUMS_TIMEZONES` - Get all supported timezone identifiers [Required]

**Key parameters**:
- No required parameters; returns complete timezone list

**Pitfalls**:
- Timezone identifiers use IANA format (e.g., 'America/New_York', 'Europe/London')
- List is static and rarely changes; cache results when possible
- Use these exact timezone strings when configuring scenario schedules

### 4. Scenario Configuration Lookup

**When to use**: User needs to configure scenarios with correct language and timezone values

**Tool sequence**:
1. `MAKE_LIST_ENUMS_LANGUAGES` - Get valid language codes [Required]
2. `MAKE_LIST_ENUMS_TIMEZONES` - Get valid timezone identifiers [Required]

**Key parameters**:
- No parameters needed for either call

**Pitfalls**:
- Always verify language and timezone values against these enums before using in configuration
- Using invalid values in scenario configuration will cause errors

## Common Patterns

### Enum Validation

Before configuring any Make scenario properties that accept language or timezone:
```
1. Call MAKE_LIST_ENUMS_LANGUAGES or MAKE_LIST_ENUMS_TIMEZONES
2. Verify the desired value exists in the returned list
3. Use the exact string value from the enum list
```

### Operations Monitoring

```
1. Call MAKE_GET_OPERATIONS with date range filters
2. Analyze operation counts, statuses, and error rates
3. Identify failed operations for troubleshooting
```

### Caching Strategy for Enums

Since language and timezone lists are static:
```
1. Call MAKE_LIST_ENUMS_LANGUAGES once at workflow start
2. Store results in memory or local cache
3. Validate user inputs against cached values
4. Refresh cache only when starting a new session
```

### Operations Analysis Workflow

For scenario health monitoring:
```
1. Call MAKE_GET_OPERATIONS with recent date range
2. Group operations by scenario ID
3. Calculate success/failure ratios per scenario
4. Identify scenarios with high error rates
5. Report findings to user or notification channel
```

### Integration with Other Toolkits

Make workflows often connect to other apps. Compose multi-tool workflows:
```
1. Call RUBE_SEARCH_TOOLS to find tools for the target app
2. Connect required toolkits via RUBE_MANAGE_CONNECTIONS
3. Use Make operations data to understand workflow execution patterns
4. Execute equivalent workflows directly via individual app toolkits
```

## Known Pitfalls

**Limited Toolkit**:
- The Make toolkit in Composio currently has limited tools (operations, languages, timezones)
- For full scenario management (creating, editing, running scenarios), consider using Make's native API
- Always call RUBE_SEARCH_TOOLS to check for newly available tools
- The toolkit may be expanded over time; re-check periodically

**Operations Data**:
- Operation records may have significant volume for active accounts
- Always filter by date range to avoid fetching excessive data
- Operation counts relate to Make's pricing tiers and quota usage
- Failed operations should be investigated; they may indicate scenario co
