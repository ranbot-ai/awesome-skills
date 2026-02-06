---
name: posthog-automation
description: Automate PostHog tasks via Rube MCP (Composio): events, feature flags, projects, user profiles, annotations. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, json, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/posthog-automation
---


# PostHog Automation via Rube MCP

Automate PostHog product analytics and feature flag management through Composio's PostHog toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active PostHog connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `posthog`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `posthog`
3. If connection is not ACTIVE, follow the returned auth link to complete PostHog authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Capture Events

**When to use**: User wants to send event data to PostHog for analytics tracking

**Tool sequence**:
1. `POSTHOG_CAPTURE_EVENT` - Send one or more events to PostHog [Required]

**Key parameters**:
- `event`: Event name (e.g., '$pageview', 'user_signed_up', 'purchase_completed')
- `distinct_id`: Unique user identifier (required)
- `properties`: Object with event-specific properties
- `timestamp`: ISO 8601 timestamp (optional; defaults to server time)

**Pitfalls**:
- `distinct_id` is required for every event; identifies the user/device
- PostHog system events use `$` prefix (e.g., '$pageview', '$identify')
- Custom events should NOT use the `$` prefix
- Properties are freeform; maintain consistent schemas across events
- Events are processed asynchronously; ingestion delay is typically seconds

### 2. List and Filter Events

**When to use**: User wants to browse or search through captured events

**Tool sequence**:
1. `POSTHOG_LIST_AND_FILTER_PROJECT_EVENTS` - Query events with filters [Required]

**Key parameters**:
- `project_id`: PostHog project ID (required)
- `event`: Filter by event name
- `person_id`: Filter by person ID
- `after`: Events after this ISO 8601 timestamp
- `before`: Events before this ISO 8601 timestamp
- `limit`: Maximum events to return
- `offset`: Pagination offset

**Pitfalls**:
- `project_id` is required; resolve via LIST_PROJECTS first
- Date filters use ISO 8601 format (e.g., '2024-01-15T00:00:00Z')
- Large event volumes require pagination; use `offset` and `limit`
- Results are returned in reverse chronological order by default
- Event properties are nested; parse carefully

### 3. Manage Feature Flags

**When to use**: User wants to create, view, or manage feature flags

**Tool sequence**:
1. `POSTHOG_LIST_AND_MANAGE_PROJECT_FEATURE_FLAGS` - List existing feature flags [Required]
2. `POSTHOG_RETRIEVE_FEATURE_FLAG_DETAILS` - Get detailed flag configuration [Optional]
3. `POSTHOG_CREATE_FEATURE_FLAGS_FOR_PROJECT` - Create a new feature flag [Optional]

**Key parameters**:
- For listing: `project_id` (required)
- For details: `project_id`, `id` (feature flag ID)
- For creation:
  - `project_id`: Target project
  - `key`: Flag key (e.g., 'new-dashboard-beta')
  - `name`: Human-readable name
  - `filters`: Targeting rules and rollout percentage
  - `active`: Whether the flag is enabled

**Pitfalls**:
- Feature flag `key` must be unique within a project
- Flag keys should use kebab-case (e.g., 'my-feature-flag')
- `filters` define targeting groups with properties and rollout percentages
- Creating a flag with `active: true` immediately enables it for matching users
- Flag changes take effect within seconds due to PostHog's polling mechanism

### 4. Manage Projects

**When to use**: User wants to list or inspect PostHog projects and organizations

**Tool sequence**:
1. `POSTHOG_LIST_PROJECTS_IN_ORGANIZATION_WITH_PAGINATION` - List all projects [Required]

**Key parameters**:
- `organization_id`: Organization identifier (may be optional depending on auth)
- `limit`: Number of results per page
- `offset`: Pagination offset

**Pitfalls**:
- Project IDs are numeric; used as parameters in most other endpoints
- Organization ID may be required; check your PostHog setup
- Pagination is offset-based; iterate until results are empty
- Project settings include API keys and configuration details

### 5. User Profile and Authentication

**When to use**: User wants to check current user details or verify API access

**Tool sequence**:
1. `POSTHOG_WHOAMI` - Get current API user information [Optional]
2. `POSTHOG_RETRIEVE_CURRENT_USER_PROFILE` - Get detailed user profile [Optional]

**Key parameters**:
- No required parameters for either call
- Returns current authenticated user's details, permissions, and organization info

**Pitfalls**:
- WHOAMI is a lightweight check; use for verifying API connectivity
- User profile includes organization membership and permissions
- These endpoints confirm the API key's access level and scope

## Common Patterns

### ID Resolution

**Organization -> Project ID**:
```
1. Call POSTHOG_LIST_PROJECTS_IN_
