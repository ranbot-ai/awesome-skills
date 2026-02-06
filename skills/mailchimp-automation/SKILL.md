---
name: mailchimp-automation
description: Automate Mailchimp email marketing including campaigns, audiences, subscribers, segments, and analytics via Rube MCP (Composio). Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/mailchimp-automation
---


# Mailchimp Automation via Rube MCP

Automate Mailchimp email marketing workflows including campaign creation and sending, audience/list management, subscriber operations, segmentation, and performance analytics through Composio's Mailchimp toolkit.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Mailchimp connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `mailchimp`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `mailchimp`
3. If connection is not ACTIVE, follow the returned auth link to complete Mailchimp OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Create and Send Email Campaigns

**When to use**: User wants to create, configure, test, and send an email campaign.

**Tool sequence**:
1. `MAILCHIMP_GET_LISTS_INFO` - List available audiences and get list_id [Prerequisite]
2. `MAILCHIMP_ADD_CAMPAIGN` - Create a new campaign with type, audience, subject, from name [Required]
3. `MAILCHIMP_SET_CAMPAIGN_CONTENT` - Set HTML content for the campaign [Required]
4. `MAILCHIMP_SEND_TEST_EMAIL` - Send preview to reviewers before live send [Optional]
5. `MAILCHIMP_SEND_CAMPAIGN` - Send the campaign immediately [Required]
6. `MAILCHIMP_SCHEDULE_CAMPAIGN` - Schedule for future delivery instead of immediate send [Optional]

**Key parameters for MAILCHIMP_ADD_CAMPAIGN**:
- `type`: "regular", "plaintext", "rss", or "variate" (required)
- `recipients__list__id`: Audience/list ID for recipients
- `settings__subject__line`: Email subject line
- `settings__from__name`: Sender display name
- `settings__reply__to`: Reply-to email address (required for sending)
- `settings__title`: Internal campaign title
- `settings__preview__text`: Preview text shown in inbox

**Key parameters for MAILCHIMP_SET_CAMPAIGN_CONTENT**:
- `campaign_id`: Campaign ID from creation step (required)
- `html`: Raw HTML content for the email
- `plain_text`: Plain-text version (auto-generated if omitted)
- `template__id`: Use a pre-built template instead of raw HTML

**Pitfalls**:
- `MAILCHIMP_SEND_CAMPAIGN` is irreversible; always send a test email first and get explicit user approval
- Campaign must be in "save" (draft) status with valid audience, subject, from name, verified email, and content before sending
- `MAILCHIMP_SCHEDULE_CAMPAIGN` requires a valid future datetime; past timestamps fail
- Templates and HTML content must include compliant footer/unsubscribe merge tags
- Mailchimp uses double-underscore notation for nested params (e.g., `settings__subject__line`)

### 2. Manage Audiences and Subscribers

**When to use**: User wants to view audiences, list subscribers, or check subscriber details.

**Tool sequence**:
1. `MAILCHIMP_GET_LISTS_INFO` - List all audiences with member counts [Required]
2. `MAILCHIMP_GET_LIST_INFO` - Get details for a specific audience [Optional]
3. `MAILCHIMP_LIST_MEMBERS_INFO` - List members with status filter and pagination [Required]
4. `MAILCHIMP_SEARCH_MEMBERS` - Search by email or name across lists [Optional]
5. `MAILCHIMP_GET_MEMBER_INFO` - Get detailed profile for a specific subscriber [Optional]
6. `MAILCHIMP_LIST_SEGMENTS` - List segments within an audience [Optional]

**Key parameters for MAILCHIMP_LIST_MEMBERS_INFO**:
- `list_id`: Audience ID (required)
- `status`: "subscribed", "unsubscribed", "cleaned", "pending", "transactional", "archived"
- `count`: Records per page (default 10, max 1000)
- `offset`: Pagination offset (default 0)
- `sort_field`: "timestamp_opt", "timestamp_signup", or "last_changed"
- `fields`: Comma-separated list to limit response size

**Pitfalls**:
- `stats.avg_open_rate` and `stats.avg_click_rate` are 0-1 fractions, NOT 0-100 percentages
- Always use `status="subscribed"` to filter active subscribers; omitting returns all statuses
- Must paginate using `count` and `offset` until collected members match `total_items`
- Large list responses may be truncated; data is under `response.data.members`

### 3. Add and Update Subscribers

**When to use**: User wants to add new subscribers, update existing ones, or bulk-manage list membership.

**Tool sequence**:
1. `MAILCHIMP_GET_LIST_INFO` - Validate target audience exists [Prerequisite]
2. `MAILCHIMP_SEARCH_MEMBERS` - Check if contact already exists [Optional]
3. `MAILCHIMP_ADD_OR_UPDATE_LIST_MEMBER` - Upsert subscriber (create or update) [Required]
4. `MAILCHIMP_ADD_MEMBER_TO_LIST` - Add new subscriber (create only) [Optional]
5. `MAILCHIMP_BATCH_ADD_OR_REMOVE_MEMBERS` - Bulk manage segment membership [Optional]

**Key parameters for MAILCHIMP_ADD_OR_UPDATE_LIST_MEMBER**:
- `list_id`: Audience ID (required)
- `subscriber_hash`: MD5 hash of lo
