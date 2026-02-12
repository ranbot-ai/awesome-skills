---
name: freshdesk-automation
description: Automate Freshdesk helpdesk operations including tickets, contacts, companies, notes, and replies via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/freshdesk-automation
---


# Freshdesk Automation via Rube MCP

Automate Freshdesk customer support workflows including ticket management, contact and company operations, notes, replies, and ticket search through Composio's Freshdesk toolkit.

**Toolkit docs**: [composio.dev/toolkits/freshdesk](https://composio.dev/toolkits/freshdesk)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Freshdesk connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `freshdesk`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `freshdesk`
3. If connection is not ACTIVE, follow the returned auth link to complete Freshdesk authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Manage Tickets

**When to use**: User wants to create a new support ticket, update an existing ticket, or view ticket details.

**Tool sequence**:
1. `FRESHDESK_SEARCH_CONTACTS` - Find requester by email to get requester_id [Optional]
2. `FRESHDESK_LIST_TICKET_FIELDS` - Check available custom fields and statuses [Optional]
3. `FRESHDESK_CREATE_TICKET` - Create a new ticket with subject, description, requester info [Required]
4. `FRESHDESK_UPDATE_TICKET` - Modify ticket status, priority, assignee, or other fields [Optional]
5. `FRESHDESK_VIEW_TICKET` - Retrieve full ticket details by ID [Optional]

**Key parameters for FRESHDESK_CREATE_TICKET**:
- `subject`: Ticket subject (required)
- `description`: HTML content of the ticket (required)
- `email`: Requester email (at least one requester identifier required)
- `requester_id`: User ID of requester (alternative to email)
- `status`: 2=Open, 3=Pending, 4=Resolved, 5=Closed (default 2)
- `priority`: 1=Low, 2=Medium, 3=High, 4=Urgent (default 1)
- `source`: 1=Email, 2=Portal, 3=Phone, 7=Chat (default 2)
- `responder_id`: Agent ID to assign the ticket to
- `group_id`: Group to assign the ticket to
- `tags`: Array of tag strings
- `custom_fields`: Object with `cf_<field_name>` keys

**Pitfalls**:
- At least one requester identifier is required: `requester_id`, `email`, `phone`, `facebook_id`, `twitter_id`, or `unique_external_id`
- If `phone` is provided without `email`, then `name` becomes mandatory
- `description` supports HTML formatting
- `attachments` field expects multipart/form-data format, not file paths or URLs
- Custom field keys must be prefixed with `cf_` (e.g., `cf_reference_number`)
- Status and priority are integers, not strings

### 2. Search and Filter Tickets

**When to use**: User wants to find tickets by status, priority, date range, agent, or custom fields.

**Tool sequence**:
1. `FRESHDESK_GET_TICKETS` - List tickets with simple filters (status, priority, agent) [Required]
2. `FRESHDESK_GET_SEARCH` - Advanced ticket search with query syntax [Required]
3. `FRESHDESK_VIEW_TICKET` - Get full details for specific tickets from results [Optional]
4. `FRESHDESK_LIST_TICKET_FIELDS` - Check available fields for search queries [Optional]

**Key parameters for FRESHDESK_GET_TICKETS**:
- `status`: Filter by status integer (2=Open, 3=Pending, 4=Resolved, 5=Closed)
- `priority`: Filter by priority integer (1-4)
- `agent_id`: Filter by assigned agent
- `requester_id`: Filter by requester
- `email`: Filter by requester email
- `created_since`: ISO 8601 timestamp
- `page` / `per_page`: Pagination (default 30 per page)
- `sort_by` / `sort_order`: Sort field and direction

**Key parameters for FRESHDESK_GET_SEARCH**:
- `query`: Query string like `"status:2 AND priority:3"` or `"(created_at:>'2024-01-01' AND tag:'urgent')"`
- `page`: Page number (1-10, max 300 total results)

**Pitfalls**:
- `FRESHDESK_GET_SEARCH` query must be enclosed in double quotes
- Query string limited to 512 characters
- Maximum 10 pages (300 results) from search endpoints
- Date fields in queries use UTC format YYYY-MM-DD
- Use `null` keyword to find tickets with empty fields (e.g., `"agent_id:null"`)
- `FRESHDESK_LIST_ALL_TICKETS` takes no parameters and returns all tickets (use GET_TICKETS for filtering)

### 3. Reply to and Add Notes on Tickets

**When to use**: User wants to send a reply to a customer, add internal notes, or view conversation history.

**Tool sequence**:
1. `FRESHDESK_VIEW_TICKET` - Verify ticket exists and check current state [Prerequisite]
2. `FRESHDESK_REPLY_TO_TICKET` - Send a public reply to the requester [Required]
3. `FRESHDESK_ADD_NOTE_TO_TICKET` - Add a private or public note [Required]
4. `FRESHDESK_LIST_ALL_TICKET_CONVERSATIONS` - View all messages and notes on a ticket [Optional]
5. `FRESHDESK_UPDATE_CONVERSATIONS` - Edit an existing note [Optional]

**Key parameters for FRESHDESK_REPLY_TO_TICKET**:
- `ticket_id`: Ticket ID (inte
