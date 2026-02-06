---
name: activecampaign-automation
description: Automate ActiveCampaign tasks via Rube MCP (Composio): manage contacts, tags, list subscriptions, automation enrollment, and tasks. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai, llm]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/activecampaign-automation
---


# ActiveCampaign Automation via Rube MCP

Automate ActiveCampaign CRM and marketing automation operations through Composio's ActiveCampaign toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active ActiveCampaign connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `active_campaign`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `active_campaign`
3. If connection is not ACTIVE, follow the returned auth link to complete ActiveCampaign authentication
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Find Contacts

**When to use**: User wants to create new contacts or look up existing ones

**Tool sequence**:
1. `ACTIVE_CAMPAIGN_FIND_CONTACT` - Search for an existing contact [Optional]
2. `ACTIVE_CAMPAIGN_CREATE_CONTACT` - Create a new contact [Required]

**Key parameters for find**:
- `email`: Search by email address
- `id`: Search by ActiveCampaign contact ID
- `phone`: Search by phone number

**Key parameters for create**:
- `email`: Contact email address (required)
- `first_name`: Contact first name
- `last_name`: Contact last name
- `phone`: Contact phone number
- `organization_name`: Contact's organization
- `job_title`: Contact's job title
- `tags`: Comma-separated list of tags to apply

**Pitfalls**:
- `email` is the only required field for contact creation
- Phone search uses a general search parameter internally; it may return partial matches
- When combining `email` and `phone` in FIND_CONTACT, results are filtered client-side
- Tags provided during creation are applied immediately
- Creating a contact with an existing email may update the existing contact

### 2. Manage Contact Tags

**When to use**: User wants to add or remove tags from contacts

**Tool sequence**:
1. `ACTIVE_CAMPAIGN_FIND_CONTACT` - Find contact by email or ID [Prerequisite]
2. `ACTIVE_CAMPAIGN_MANAGE_CONTACT_TAG` - Add or remove tags [Required]

**Key parameters**:
- `action`: 'Add' or 'Remove' (required)
- `tags`: Tag names as comma-separated string or array of strings (required)
- `contact_id`: Contact ID (provide this or contact_email)
- `contact_email`: Contact email address (alternative to contact_id)

**Pitfalls**:
- `action` values are capitalized: 'Add' or 'Remove' (not lowercase)
- Tags can be a comma-separated string ('tag1, tag2') or an array (['tag1', 'tag2'])
- Either `contact_id` or `contact_email` must be provided; `contact_id` takes precedence
- Adding a tag that does not exist creates it automatically
- Removing a non-existent tag is a no-op (does not error)

### 3. Manage List Subscriptions

**When to use**: User wants to subscribe or unsubscribe contacts from lists

**Tool sequence**:
1. `ACTIVE_CAMPAIGN_FIND_CONTACT` - Find the contact [Prerequisite]
2. `ACTIVE_CAMPAIGN_MANAGE_LIST_SUBSCRIPTION` - Subscribe or unsubscribe [Required]

**Key parameters**:
- `action`: 'subscribe' or 'unsubscribe' (required)
- `list_id`: Numeric list ID string (required)
- `email`: Contact email address (provide this or contact_id)
- `contact_id`: Numeric contact ID string (alternative to email)

**Pitfalls**:
- `action` values are lowercase: 'subscribe' or 'unsubscribe'
- `list_id` is a numeric string (e.g., '2'), not the list name
- List IDs can be retrieved via the GET /api/3/lists endpoint (not available as a Composio tool; use the ActiveCampaign UI)
- If both `email` and `contact_id` are provided, `contact_id` takes precedence
- Unsubscribing changes status to '2' (unsubscribed) but the relationship record persists

### 4. Add Contacts to Automations

**When to use**: User wants to enroll a contact in an automation workflow

**Tool sequence**:
1. `ACTIVE_CAMPAIGN_FIND_CONTACT` - Verify contact exists [Prerequisite]
2. `ACTIVE_CAMPAIGN_ADD_CONTACT_TO_AUTOMATION` - Enroll contact in automation [Required]

**Key parameters**:
- `contact_email`: Email of the contact to enroll (required)
- `automation_id`: ID of the target automation (required)

**Pitfalls**:
- The contact must already exist in ActiveCampaign
- Automations can only be created through the ActiveCampaign UI, not via API
- `automation_id` must reference an existing, active automation
- The tool performs a two-step process: lookup contact by email, then enroll
- Automation IDs can be found in the ActiveCampaign UI or via GET /api/3/automations

### 5. Create Contact Tasks

**When to use**: User wants to create follow-up tasks associated with contacts

**Tool sequence**:
1. `ACTIVE_CAMPAIGN_FIND_CONTACT` - Find the contact to associate the task with [Prerequisite]
2. `ACTIVE_CAMPAIGN_CREATE_CONTACT_TASK` - Create the task [Required]

**Key parameters**:
- `re
