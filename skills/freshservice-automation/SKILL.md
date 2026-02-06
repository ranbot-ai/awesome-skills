---
name: freshservice-automation
description: Automate Freshservice ITSM tasks via Rube MCP (Composio): create/update tickets, bulk operations, service requests, and outbound emails. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/freshservice-automation
---


# Freshservice Automation via Rube MCP

Automate Freshservice IT Service Management operations through Composio's Freshservice toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Freshservice connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `freshservice`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `freshservice`
3. If connection is not ACTIVE, follow the returned auth link to complete Freshservice authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. List and Search Tickets

**When to use**: User wants to find, list, or search for tickets

**Tool sequence**:
1. `FRESHSERVICE_LIST_TICKETS` - List tickets with optional filtering and pagination [Required]
2. `FRESHSERVICE_GET_TICKET` - Get detailed information for a specific ticket [Optional]

**Key parameters for listing**:
- `filter`: Predefined filter ('all_tickets', 'deleted', 'spam', 'watching')
- `updated_since`: ISO 8601 timestamp to get tickets updated after this time
- `order_by`: Sort field ('created_at', 'updated_at', 'status', 'priority')
- `order_type`: Sort direction ('asc' or 'desc')
- `page`: Page number (1-indexed)
- `per_page`: Results per page (1-100, default 30)
- `include`: Additional fields ('requester', 'stats', 'description', 'conversations', 'assets')

**Key parameters for get**:
- `ticket_id`: Unique ticket ID or display_id
- `include`: Additional fields to include

**Pitfalls**:
- By default, only tickets created within the past 30 days are returned
- Use `updated_since` to retrieve older tickets
- Each `include` value consumes additional API credits
- `page` is 1-indexed; minimum value is 1
- `per_page` max is 100; default is 30
- Ticket IDs can be the internal ID or the display_id shown in the UI

### 2. Create a Ticket

**When to use**: User wants to log a new incident or request

**Tool sequence**:
1. `FRESHSERVICE_CREATE_TICKET` - Create a new ticket [Required]

**Key parameters**:
- `subject`: Ticket subject line (required)
- `description`: HTML description of the ticket (required)
- `status`: Ticket status - 2 (Open), 3 (Pending), 4 (Resolved), 5 (Closed) (required)
- `priority`: Ticket priority - 1 (Low), 2 (Medium), 3 (High), 4 (Urgent) (required)
- `email`: Requester's email address (provide either email or requester_id)
- `requester_id`: User ID of the requester
- `type`: Ticket type ('Incident' or 'Service Request')
- `source`: Channel - 1 (Email), 2 (Portal), 3 (Phone), 4 (Chat), 5 (Twitter), 6 (Facebook)
- `impact`: Impact level - 1 (Low), 2 (Medium), 3 (High)
- `urgency`: Urgency level - 1 (Low), 2 (Medium), 3 (High), 4 (Critical)

**Pitfalls**:
- `subject`, `description`, `status`, and `priority` are all required
- Either `email` or `requester_id` must be provided to identify the requester
- Status and priority use numeric codes, not string names
- Description supports HTML formatting
- If email does not match an existing contact, a new contact is created

### 3. Bulk Update Tickets

**When to use**: User wants to update multiple tickets at once

**Tool sequence**:
1. `FRESHSERVICE_LIST_TICKETS` - Find tickets to update [Prerequisite]
2. `FRESHSERVICE_BULK_UPDATE_TICKETS` - Update multiple tickets [Required]

**Key parameters**:
- `ids`: Array of ticket IDs to update (required)
- `update_fields`: Dictionary of fields to update (required)
  - Allowed keys: 'subject', 'description', 'status', 'priority', 'responder_id', 'group_id', 'type', 'tags', 'custom_fields'

**Pitfalls**:
- Bulk update performs sequential updates internally; large batches may take time
- All specified tickets receive the same field updates
- If one ticket update fails, others may still succeed; check response for individual results
- Cannot selectively update different fields per ticket in a single call
- Custom fields must use their internal field names, not display names

### 4. Create Ticket via Outbound Email

**When to use**: User wants to create a ticket by sending an outbound email notification

**Tool sequence**:
1. `FRESHSERVICE_CREATE_TICKET_OUTBOUND_EMAIL` - Create ticket with email notification [Required]

**Key parameters**:
- `email`: Requester's email address (required)
- `subject`: Email subject / ticket subject (required)
- `description`: HTML email body content
- `status`: Ticket status (2=Open, 3=Pending, 4=Resolved, 5=Closed)
- `priority`: Ticket priority (1=Low, 2=Medium, 3=High, 4=Urgent)
- `cc_emails`: Array of CC email addresses
- `email_config_id`: Email configuration ID for the sender address
- `name`: Requester name

**Pitfalls**:
- This creates a standard ticket via the /api/v2/tickets endpoint wh
