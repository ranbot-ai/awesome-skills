---
name: pagerduty-automation
description: Automate PagerDuty tasks via Rube MCP (Composio): manage incidents, services, schedules, escalation policies, and on-call rotations. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/pagerduty-automation
---


# PagerDuty Automation via Rube MCP

Automate PagerDuty incident management and operations through Composio's PagerDuty toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active PagerDuty connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `pagerduty`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `pagerduty`
3. If connection is not ACTIVE, follow the returned auth link to complete PagerDuty authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Manage Incidents

**When to use**: User wants to create, update, acknowledge, or resolve incidents

**Tool sequence**:
1. `PAGERDUTY_FETCH_INCIDENT_LIST` - List incidents with filters [Required]
2. `PAGERDUTY_RETRIEVE_INCIDENT_BY_INCIDENT_ID` - Get specific incident details [Optional]
3. `PAGERDUTY_CREATE_INCIDENT_RECORD` - Create a new incident [Optional]
4. `PAGERDUTY_UPDATE_INCIDENT_BY_ID` - Update incident status or assignment [Optional]
5. `PAGERDUTY_POST_INCIDENT_NOTE_USING_ID` - Add a note to an incident [Optional]
6. `PAGERDUTY_SNOOZE_INCIDENT_BY_DURATION` - Snooze an incident for a period [Optional]

**Key parameters**:
- `statuses[]`: Filter by status ('triggered', 'acknowledged', 'resolved')
- `service_ids[]`: Filter by service IDs
- `urgencies[]`: Filter by urgency ('high', 'low')
- `title`: Incident title (for creation)
- `service`: Service object with `id` and `type` (for creation)
- `status`: New status for update operations

**Pitfalls**:
- Incident creation requires a `service` object with both `id` and `type: 'service_reference'`
- Status transitions follow: triggered -> acknowledged -> resolved
- Cannot transition from resolved back to triggered directly
- `PAGERDUTY_UPDATE_INCIDENT_BY_ID` requires the incident ID as a path parameter
- Snooze duration is in seconds; the incident re-triggers after the snooze period

### 2. Inspect Incident Alerts and Analytics

**When to use**: User wants to review alerts within an incident or analyze incident metrics

**Tool sequence**:
1. `PAGERDUTY_GET_ALERTS_BY_INCIDENT_ID` - List alerts for an incident [Required]
2. `PAGERDUTY_GET_INCIDENT_ALERT_DETAILS` - Get details of a specific alert [Optional]
3. `PAGERDUTY_FETCH_INCIDENT_ANALYTICS_BY_ID` - Get incident analytics/metrics [Optional]

**Key parameters**:
- `incident_id`: The incident ID
- `alert_id`: Specific alert ID within the incident
- `statuses[]`: Filter alerts by status

**Pitfalls**:
- An incident can have multiple alerts; each alert has its own status
- Alert IDs are scoped to the incident
- Analytics data includes response times, engagement metrics, and resolution times

### 3. Manage Services

**When to use**: User wants to create, update, or list services

**Tool sequence**:
1. `PAGERDUTY_RETRIEVE_LIST_OF_SERVICES` - List all services [Required]
2. `PAGERDUTY_RETRIEVE_SERVICE_BY_ID` - Get service details [Optional]
3. `PAGERDUTY_CREATE_NEW_SERVICE` - Create a new technical service [Optional]
4. `PAGERDUTY_UPDATE_SERVICE_BY_ID` - Update service configuration [Optional]
5. `PAGERDUTY_CREATE_INTEGRATION_FOR_SERVICE` - Add an integration to a service [Optional]
6. `PAGERDUTY_CREATE_BUSINESS_SERVICE` - Create a business service [Optional]
7. `PAGERDUTY_UPDATE_BUSINESS_SERVICE_BY_ID` - Update a business service [Optional]

**Key parameters**:
- `name`: Service name
- `escalation_policy`: Escalation policy object with `id` and `type`
- `alert_creation`: Alert creation mode ('create_alerts_and_incidents' or 'create_incidents')
- `status`: Service status ('active', 'warning', 'critical', 'maintenance', 'disabled')

**Pitfalls**:
- Creating a service requires an existing escalation policy
- Business services are different from technical services; they represent business-level groupings
- Service integrations define how alerts are created (email, API, events)
- Disabling a service stops all incident creation for that service

### 4. Manage Schedules and On-Call

**When to use**: User wants to view or manage on-call schedules and rotations

**Tool sequence**:
1. `PAGERDUTY_GET_SCHEDULES` - List all schedules [Required]
2. `PAGERDUTY_RETRIEVE_SCHEDULE_BY_ID` - Get specific schedule details [Optional]
3. `PAGERDUTY_CREATE_NEW_SCHEDULE_LAYER` - Create a new schedule [Optional]
4. `PAGERDUTY_UPDATE_SCHEDULE_BY_ID` - Update an existing schedule [Optional]
5. `PAGERDUTY_RETRIEVE_ONCALL_LIST` - View who is currently on-call [Optional]
6. `PAGERDUTY_CREATE_SCHEDULE_OVERRIDES_CONFIGURATION` - Create temporary overrides [Optional]
7. `PAGERDUTY_DELETE_SCHEDULE_OVERRIDE_BY_ID` - Remove an override [Optional]
8. `PAGERDUTY_RETRIEVE_USERS_BY_SCHEDULE_ID` - List
