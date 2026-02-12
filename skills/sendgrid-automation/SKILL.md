---
name: sendgrid-automation
description: Automate SendGrid email operations including sending emails, managing contacts/lists, sender identities, templates, and analytics via Rube MCP (Composio). Always search tools first for current schemas
category: Development & Code Tools
source: composio
tags: [html, api, gmail, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/sendgrid-automation
---


# SendGrid Automation via Rube MCP

Automate SendGrid email delivery workflows including marketing campaigns (Single Sends), contact and list management, sender identity setup, and email analytics through Composio's SendGrid toolkit.

**Toolkit docs**: [composio.dev/toolkits/sendgrid](https://composio.dev/toolkits/sendgrid)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active SendGrid connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `sendgrid`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `sendgrid`
3. If connection is not ACTIVE, follow the returned auth link to complete SendGrid API key authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Send Marketing Campaigns (Single Sends)

**When to use**: User wants to create and send a marketing email campaign to a contact list or segment.

**Tool sequence**:
1. `SENDGRID_RETRIEVE_ALL_LISTS` - List available marketing lists to target [Prerequisite]
2. `SENDGRID_CREATE_A_LIST` - Create a new list if needed [Optional]
3. `SENDGRID_ADD_OR_UPDATE_A_CONTACT` - Add contacts to the list [Optional]
4. `SENDGRID_GET_ALL_SENDER_IDENTITIES` - Get verified sender ID [Prerequisite]
5. `SENDGRID_CREATE_SINGLE_SEND` - Create the campaign with content, sender, and recipients [Required]

**Key parameters for SENDGRID_CREATE_SINGLE_SEND**:
- `name`: Campaign name (required)
- `email__config__subject`: Email subject line
- `email__config__html__content`: HTML body content
- `email__config__plain__content`: Plain text version
- `email__config__sender__id`: Verified sender identity ID
- `email__config__design__id`: Use instead of html_content for pre-built designs
- `send__to__list__ids`: Array of list UUIDs to send to
- `send__to__segment__ids`: Array of segment UUIDs
- `send__to__all`: true to send to all contacts
- `email__config__suppression__group__id` or `email__config__custom__unsubscribe__url`: One required for compliance

**Pitfalls**:
- Setting `send_at` on CREATE does NOT schedule the send; it only prepopulates the UI date; use the Schedule endpoint separately
- `send_at: "now"` is only valid with the Schedule endpoint, not CREATE
- Must provide either `suppression_group_id` or `custom_unsubscribe_url` for unsubscribe compliance
- Sender must be verified before use; check with `SENDGRID_GET_ALL_SENDER_IDENTITIES`
- Nested params use double-underscore notation (e.g., `email__config__subject`)

### 2. Manage Contacts and Lists

**When to use**: User wants to create contact lists, add/update contacts, search for contacts, or remove contacts from lists.

**Tool sequence**:
1. `SENDGRID_RETRIEVE_ALL_LISTS` - List all marketing lists [Required]
2. `SENDGRID_CREATE_A_LIST` - Create a new contact list [Optional]
3. `SENDGRID_GET_A_LIST_BY_ID` - Get list details and sample contacts [Optional]
4. `SENDGRID_ADD_OR_UPDATE_A_CONTACT` - Upsert contacts with list association [Required]
5. `SENDGRID_GET_CONTACTS_BY_EMAILS` - Look up contacts by email [Optional]
6. `SENDGRID_GET_CONTACTS_BY_IDENTIFIERS` - Look up contacts by email, phone, or external ID [Optional]
7. `SENDGRID_GET_LIST_CONTACT_COUNT` - Verify contact count after operations [Optional]
8. `SENDGRID_REMOVE_CONTACTS_FROM_A_LIST` - Remove contacts from a list without deleting [Optional]
9. `SENDGRID_REMOVE_LIST_AND_OPTIONAL_CONTACTS` - Delete an entire list [Optional]
10. `SENDGRID_IMPORT_CONTACTS` - Bulk import from CSV [Optional]

**Key parameters for SENDGRID_ADD_OR_UPDATE_A_CONTACT**:
- `contacts`: Array of contact objects (max 30,000 or 6MB), each with at least one identifier: `email`, `phone_number_id`, `external_id`, or `anonymous_id` (required)
- `list_ids`: Array of list UUID strings to associate contacts with

**Pitfalls**:
- `SENDGRID_ADD_OR_UPDATE_A_CONTACT` is asynchronous; returns 202 with `job_id`; contacts may take 10-30 seconds to appear
- List IDs are UUIDs (e.g., "ca7a3796-e8a8-4029-9ccb-df8937940562"), not integers
- List names must be unique; duplicate names cause 400 errors
- `SENDGRID_ADD_A_SINGLE_RECIPIENT_TO_A_LIST` uses the legacy API; prefer `SENDGRID_ADD_OR_UPDATE_A_CONTACT` with `list_ids`
- `SENDGRID_REMOVE_LIST_AND_OPTIONAL_CONTACTS` is irreversible; require explicit user confirmation
- Email addresses are automatically lowercased by SendGrid

### 3. Manage Sender Identities

**When to use**: User wants to set up or view sender identities (From addresses) for sending emails.

**Tool sequence**:
1. `SENDGRID_GET_ALL_SENDER_IDENTITIES` - List all existing sender identities [Required]
2. `SENDGRID_CREATE_A_SENDER_IDENTITY` - Create a new sender identity [Optional]
3. `SENDGRID_VIEW_A_SENDER_I
