---
name: intercom-automation
description: Automate Intercom tasks via Rube MCP (Composio): conversations, contacts, companies, segments, admins. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, json, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/intercom-automation
---


# Intercom Automation via Rube MCP

Automate Intercom operations through Composio's Intercom toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Intercom connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `intercom`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `intercom`
3. If connection is not ACTIVE, follow the returned auth link to complete Intercom OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Manage Conversations

**When to use**: User wants to create, list, search, or manage support conversations

**Tool sequence**:
1. `INTERCOM_LIST_ALL_ADMINS` - Get admin IDs for assignment [Prerequisite]
2. `INTERCOM_LIST_CONVERSATIONS` - List all conversations [Optional]
3. `INTERCOM_SEARCH_CONVERSATIONS` - Search with filters [Optional]
4. `INTERCOM_GET_CONVERSATION` - Get conversation details [Optional]
5. `INTERCOM_CREATE_CONVERSATION` - Create a new conversation [Optional]

**Key parameters**:
- `from`: Object with `type` ('user'/'lead') and `id` for conversation creator
- `body`: Message body (HTML supported)
- `id`: Conversation ID for retrieval
- `query`: Search query object with `field`, `operator`, `value`

**Pitfalls**:
- CREATE_CONVERSATION requires a contact (user/lead) as the `from` field, not an admin
- Conversation bodies support HTML; plain text is auto-wrapped in `<p>` tags
- Search query uses structured filter objects, not free-text search
- Conversation IDs are numeric strings

### 2. Reply and Manage Conversation State

**When to use**: User wants to reply to, close, reopen, or assign conversations

**Tool sequence**:
1. `INTERCOM_GET_CONVERSATION` - Get current state [Prerequisite]
2. `INTERCOM_REPLY_TO_CONVERSATION` - Add a reply [Optional]
3. `INTERCOM_ASSIGN_CONVERSATION` - Assign to admin/team [Optional]
4. `INTERCOM_CLOSE_CONVERSATION` - Close conversation [Optional]
5. `INTERCOM_REOPEN_CONVERSATION` - Reopen closed conversation [Optional]

**Key parameters**:
- `conversation_id` / `id`: Conversation ID
- `body`: Reply message body (HTML supported)
- `type`: Reply type ('admin' or 'user')
- `admin_id`: Admin ID for replies from admin, assignment, and close/reopen
- `assignee_id`: Admin or team ID for assignment
- `message_type`: 'comment' (default) or 'note' (internal)

**Pitfalls**:
- `admin_id` is REQUIRED for admin replies, close, reopen, and assignment operations
- Always fetch admin IDs first with LIST_ALL_ADMINS or IDENTIFY_AN_ADMIN
- Duplicate sends can occur on retry; implement idempotency checks
- Internal notes use `message_type: 'note'`; visible only to workspace members
- Closing requires an admin_id and optional body message

### 3. Manage Contacts

**When to use**: User wants to search, view, or manage contacts (users and leads)

**Tool sequence**:
1. `INTERCOM_SEARCH_CONTACTS` - Search contacts with filters [Required]
2. `INTERCOM_GET_A_CONTACT` - Get specific contact [Optional]
3. `INTERCOM_SHOW_CONTACT_BY_EXTERNAL_ID` - Look up by external ID [Optional]
4. `INTERCOM_LIST_CONTACTS` - List all contacts [Optional]
5. `INTERCOM_LIST_TAGS_ATTACHED_TO_A_CONTACT` - Get contact tags [Optional]
6. `INTERCOM_LIST_ATTACHED_SEGMENTS_FOR_CONTACT` - Get contact segments [Optional]
7. `INTERCOM_DETACH_A_CONTACT` - Remove contact from company [Optional]

**Key parameters**:
- `contact_id`: Contact ID for retrieval
- `external_id`: External system ID for lookup
- `query`: Search filter object with `field`, `operator`, `value`
- `pagination`: Object with `per_page` and `starting_after` cursor

**Pitfalls**:
- SEARCH_CONTACTS uses structured query filters, not free-text; format: `{field, operator, value}`
- Supported operators: `=`, `!=`, `>`, `<`, `~` (contains), `!~` (not contains), `IN`, `NIN`
- Contact types are 'user' (identified) or 'lead' (anonymous)
- LIST_CONTACTS returns paginated results; use `starting_after` cursor for pagination
- External IDs are case-sensitive

### 4. Manage Admins and Teams

**When to use**: User wants to list workspace admins or identify specific admins

**Tool sequence**:
1. `INTERCOM_LIST_ALL_ADMINS` - List all admins and teams [Required]
2. `INTERCOM_IDENTIFY_AN_ADMIN` - Get specific admin details [Optional]

**Key parameters**:
- `admin_id`: Admin ID for identification

**Pitfalls**:
- LIST_ALL_ADMINS returns both admins and teams
- Admin IDs are required for conversation replies, assignment, close, and reopen
- Teams appear in the admins list with `type: 'team'`

### 5. View Segments and Counts

**When to use**: User wants to view segments or get aggregate counts

**Tool sequence**:
1. `INTERCOM_LIST_SEGMENTS` - List all segments [Opt
