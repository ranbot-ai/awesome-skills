---
name: pipedrive-automation
description: Automate Pipedrive CRM operations including deals, contacts, organizations, activities, notes, and pipeline management via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/pipedrive-automation
---


# Pipedrive Automation via Rube MCP

Automate Pipedrive CRM workflows including deal management, contact and organization operations, activity scheduling, notes, and pipeline/stage queries through Composio's Pipedrive toolkit.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Pipedrive connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `pipedrive`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `pipedrive`
3. If connection is not ACTIVE, follow the returned auth link to complete Pipedrive OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Manage Deals

**When to use**: User wants to create a new deal, update an existing deal, or review deal details in the sales pipeline.

**Tool sequence**:
1. `PIPEDRIVE_SEARCH_ORGANIZATIONS` - Find existing org to link to the deal [Optional]
2. `PIPEDRIVE_ADD_AN_ORGANIZATION` - Create organization if none found [Optional]
3. `PIPEDRIVE_SEARCH_PERSONS` - Find existing contact to link [Optional]
4. `PIPEDRIVE_ADD_A_PERSON` - Create contact if none found [Optional]
5. `PIPEDRIVE_GET_ALL_PIPELINES` - Resolve pipeline ID [Prerequisite]
6. `PIPEDRIVE_GET_ALL_STAGES` - Resolve stage ID within the pipeline [Prerequisite]
7. `PIPEDRIVE_ADD_A_DEAL` - Create the deal with title, value, org_id, person_id, stage_id [Required]
8. `PIPEDRIVE_UPDATE_A_DEAL` - Modify deal properties after creation [Optional]
9. `PIPEDRIVE_ADD_A_PRODUCT_TO_A_DEAL` - Attach line items/products [Optional]

**Key parameters**:
- `title`: Deal title (required for creation)
- `value`: Monetary value of the deal
- `currency`: 3-letter ISO currency code (e.g., "USD")
- `pipeline_id` / `stage_id`: Numeric IDs for pipeline placement
- `org_id` / `person_id`: Link to organization and contact
- `status`: "open", "won", or "lost"
- `expected_close_date`: Format YYYY-MM-DD

**Pitfalls**:
- `title` is the only required field for `PIPEDRIVE_ADD_A_DEAL`; all others are optional
- Custom fields appear as long hash keys in responses; use dealFields endpoint to map them
- `PIPEDRIVE_UPDATE_A_DEAL` requires the numeric `id` of the deal
- Setting `status` to "lost" requires also providing `lost_reason`

### 2. Manage Contacts (Persons and Organizations)

**When to use**: User wants to create, update, search, or list contacts and companies in Pipedrive.

**Tool sequence**:
1. `PIPEDRIVE_SEARCH_PERSONS` - Search for existing person by name, email, or phone [Prerequisite]
2. `PIPEDRIVE_ADD_A_PERSON` - Create new contact if not found [Required]
3. `PIPEDRIVE_UPDATE_A_PERSON` - Modify existing contact details [Optional]
4. `PIPEDRIVE_GET_DETAILS_OF_A_PERSON` - Retrieve full contact record [Optional]
5. `PIPEDRIVE_SEARCH_ORGANIZATIONS` - Search for existing organization [Prerequisite]
6. `PIPEDRIVE_ADD_AN_ORGANIZATION` - Create new organization if not found [Required]
7. `PIPEDRIVE_UPDATE_AN_ORGANIZATION` - Modify organization properties [Optional]
8. `PIPEDRIVE_GET_DETAILS_OF_AN_ORGANIZATION` - Retrieve full org record [Optional]

**Key parameters**:
- `name`: Required for both person and organization creation
- `email`: Array of objects with `value`, `label`, `primary` fields for persons
- `phone`: Array of objects with `value`, `label`, `primary` fields for persons
- `org_id`: Link a person to an organization
- `visible_to`: 1 = owner only, 3 = entire company
- `term`: Search term for SEARCH_PERSONS / SEARCH_ORGANIZATIONS (minimum 2 characters)

**Pitfalls**:
- `PIPEDRIVE_ADD_AN_ORGANIZATION` may auto-merge with an existing org; check `response.additional_data.didMerge`
- Email and phone fields are arrays of objects, not plain strings: `[{"value": "test@example.com", "label": "work", "primary": true}]`
- `PIPEDRIVE_SEARCH_PERSONS` wildcards like `*` or `@` are NOT supported; use `PIPEDRIVE_GET_ALL_PERSONS` to list all
- Deletion via `PIPEDRIVE_DELETE_A_PERSON` or `PIPEDRIVE_DELETE_AN_ORGANIZATION` is soft-delete with 30-day retention, then permanent

### 3. Schedule and Track Activities

**When to use**: User wants to create calls, meetings, tasks, or other activities linked to deals, contacts, or organizations.

**Tool sequence**:
1. `PIPEDRIVE_SEARCH_PERSONS` or `PIPEDRIVE_GET_DETAILS_OF_A_DEAL` - Resolve linked entity IDs [Prerequisite]
2. `PIPEDRIVE_ADD_AN_ACTIVITY` - Create the activity with subject, type, due date [Required]
3. `PIPEDRIVE_UPDATE_AN_ACTIVITY` - Modify activity details or mark as done [Optional]
4. `PIPEDRIVE_GET_DETAILS_OF_AN_ACTIVITY` - Retrieve activity record [Optional]
5. `PIPEDRIVE_GET_ALL_ACTIVITIES_ASSIGNED_TO_A_PARTICULAR_USER` - List user's activities [Optional]

**Key parameters**:
- `subject`: Act
