---
name: hubspot-automation
description: Automate HubSpot CRM operations (contacts, companies, deals, tickets, properties) via Rube MCP using Composio integration. 
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/hubspot-automation
---


# HubSpot CRM Automation via Rube MCP

Automate HubSpot CRM workflows including contact/company management, deal pipeline tracking, ticket search, and custom property creation through Composio's HubSpot toolkit.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active HubSpot connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `hubspot`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `hubspot`
3. If connection is not ACTIVE, follow the returned auth link to complete HubSpot OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Manage Contacts

**When to use**: User wants to create new contacts or update existing ones in HubSpot CRM

**Tool sequence**:
1. `HUBSPOT_GET_ACCOUNT_INFO` - Verify connection and permissions (Prerequisite)
2. `HUBSPOT_SEARCH_CONTACTS_BY_CRITERIA` - Search for existing contacts to avoid duplicates (Prerequisite)
3. `HUBSPOT_READ_A_CRM_PROPERTY_BY_NAME` - Check property metadata for constrained values (Optional)
4. `HUBSPOT_CREATE_CONTACT` - Create a single contact (Required)
5. `HUBSPOT_CREATE_CONTACTS` - Batch create contacts up to 100 (Alternative)

**Key parameters**:
- `HUBSPOT_CREATE_CONTACT`: `properties` object with `email`, `firstname`, `lastname`, `phone`, `company`
- `HUBSPOT_CREATE_CONTACTS`: `inputs` array of `{properties}` objects, max 100 per batch
- `HUBSPOT_SEARCH_CONTACTS_BY_CRITERIA`: `filterGroups` array with `{filters: [{propertyName, operator, value}]}`, `properties` array of fields to return

**Pitfalls**:
- Max 100 records per batch; chunk larger imports
- 400 'Property values were not valid' if using incorrect property names or enum values
- Always search before creating to avoid duplicates
- Auth errors from GET_ACCOUNT_INFO mean all subsequent calls will fail

### 2. Manage Companies

**When to use**: User wants to create, search, or update company records

**Tool sequence**:
1. `HUBSPOT_SEARCH_COMPANIES` - Search existing companies (Prerequisite)
2. `HUBSPOT_CREATE_COMPANIES` - Batch create companies, max 100 (Required)
3. `HUBSPOT_UPDATE_COMPANIES` - Batch update existing companies (Alternative)
4. `HUBSPOT_GET_COMPANY` - Get single company details (Optional)
5. `HUBSPOT_BATCH_READ_COMPANIES_BY_PROPERTIES` - Bulk read companies by property values (Optional)

**Key parameters**:
- `HUBSPOT_CREATE_COMPANIES`: `inputs` array of `{properties}` objects, max 100
- `HUBSPOT_SEARCH_COMPANIES`: `filterGroups`, `properties`, `sorts`, `limit`, `after` (pagination cursor)

**Pitfalls**:
- Max 100 per batch; chunk larger sets
- Store returned IDs immediately for downstream operations
- Property values must match exact internal names, not display labels

### 3. Manage Deals and Pipeline

**When to use**: User wants to search deals, view pipeline stages, or track deal progress

**Tool sequence**:
1. `HUBSPOT_RETRIEVE_ALL_PIPELINES_FOR_SPECIFIED_OBJECT_TYPE` - Map pipeline and stage IDs/names (Prerequisite)
2. `HUBSPOT_SEARCH_DEALS` - Search deals with filters (Required)
3. `HUBSPOT_RETRIEVE_PIPELINE_STAGES` - Get stage details for one pipeline (Optional)
4. `HUBSPOT_RETRIEVE_OWNERS` - Get owner/rep details (Optional)
5. `HUBSPOT_GET_DEAL` - Get single deal details (Optional)
6. `HUBSPOT_LIST_DEALS` - List all deals without filters (Fallback)

**Key parameters**:
- `HUBSPOT_SEARCH_DEALS`: `filterGroups` with filters on `pipeline`, `dealstage`, `createdate`, `closedate`, `hubspot_owner_id`; `properties`, `sorts`, `limit`, `after`
- `HUBSPOT_RETRIEVE_ALL_PIPELINES_FOR_SPECIFIED_OBJECT_TYPE`: `objectType` set to `'deals'`

**Pitfalls**:
- Results nested under `response.data.results`; properties are often strings (amounts, dates)
- Stage IDs may be readable strings or opaque numeric IDs; use `label` field for display
- Filters must use internal property names (`pipeline`, `dealstage`, `createdate`), not display names
- Paginate via `paging.next.after` until absent

### 4. Search and Filter Tickets

**When to use**: User wants to find support tickets by status, date, or criteria

**Tool sequence**:
1. `HUBSPOT_SEARCH_TICKETS` - Search with filterGroups (Required)
2. `HUBSPOT_READ_ALL_PROPERTIES_FOR_OBJECT_TYPE` - Discover available property names (Fallback)
3. `HUBSPOT_GET_TICKET` - Get single ticket details (Optional)
4. `HUBSPOT_GET_TICKETS` - Bulk fetch tickets by IDs (Optional)

**Key parameters**:
- `HUBSPOT_SEARCH_TICKETS`: `filterGroups`, `properties` (only listed fields are returned), `sorts`, `limit`, `after`

**Pitfalls**:
- Incorrect `propertyName`/`operator` returns zero results without errors
- Date filtering may require epoch-ms bounds; mixing formats causes mismatches
- O
