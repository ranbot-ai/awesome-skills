---
name: gmail-automation
description: Automate Gmail tasks via Rube MCP (Composio): send/reply, search, labels, drafts, attachments. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [html, api, gmail, pdf, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/gmail-automation
---


# Gmail Automation via Rube MCP

Automate Gmail operations through Composio's Gmail toolkit via Rube MCP.

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Gmail connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `gmail`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `gmail`
3. If connection is not ACTIVE, follow the returned auth link to complete Google OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Send an Email

**When to use**: User wants to compose and send a new email

**Tool sequence**:
1. `GMAIL_SEARCH_PEOPLE` - Resolve contact name to email address [Optional]
2. `GMAIL_SEND_EMAIL` - Send the email [Required]

**Key parameters**:
- `recipient_email`: Email address or 'me' for self
- `subject`: Email subject line
- `body`: Email content (plain text or HTML)
- `is_html`: Must be `true` if body contains HTML markup
- `cc`/`bcc`: Arrays of email addresses
- `attachment`: Object with `{s3key, mimetype, name}` from prior download

**Pitfalls**:
- At least one of `recipient_email`, `cc`, or `bcc` required
- At least one of `subject` or `body` required
- Attachment `mimetype` MUST contain '/' (e.g., 'application/pdf', not 'pdf')
- Total message size limit ~25MB after base64 encoding
- Use `from_email` only for verified aliases in Gmail 'Send mail as' settings

### 2. Reply to a Thread

**When to use**: User wants to reply to an existing email conversation

**Tool sequence**:
1. `GMAIL_FETCH_EMAILS` - Find the email/thread to reply to [Prerequisite]
2. `GMAIL_REPLY_TO_THREAD` - Send reply within the thread [Required]

**Key parameters**:
- `thread_id`: Hex string from FETCH_EMAILS (e.g., '169eefc8138e68ca')
- `message_body`: Reply content
- `recipient_email`: Reply recipient
- `is_html`: Set `true` for HTML content

**Pitfalls**:
- `thread_id` must be hex string; prefixes like 'msg-f:' are auto-stripped
- Legacy Gmail web UI IDs (e.g., 'FMfcgz...') are NOT supported
- Subject is inherited from original thread; setting it creates a new thread instead
- Do NOT include subject parameter to stay within thread

### 3. Search and Filter Emails

**When to use**: User wants to find specific emails by sender, subject, date, label, etc.

**Tool sequence**:
1. `GMAIL_FETCH_EMAILS` - Search with Gmail query syntax [Required]
2. `GMAIL_FETCH_MESSAGE_BY_MESSAGE_ID` - Get full message details for selected results [Optional]

**Key parameters**:
- `query`: Gmail search syntax (from:, to:, subject:, is:unread, has:attachment, after:YYYY/MM/DD, before:YYYY/MM/DD)
- `max_results`: 1-500 messages per page
- `label_ids`: System IDs like 'INBOX', 'UNREAD'
- `include_payload`: Set `true` to get full message content
- `ids_only`: Set `true` for just message IDs
- `page_token`: For pagination (from `nextPageToken`)

**Pitfalls**:
- Returns max ~500 per page; follow `nextPageToken` via `page_token` until absent
- `resultSizeEstimate` is approximate, not exact count
- Use 'is:' for states (is:unread, is:snoozed, is:starred)
- Use 'label:' ONLY for user-created labels
- Common mistake: 'label:snoozed' is WRONG — use 'is:snoozed'
- `include_payload=true` on broad searches creates huge responses; default to metadata
- Custom labels require label ID (e.g., 'Label_123'), NOT label name

### 4. Manage Labels

**When to use**: User wants to create, modify, or organize labels

**Tool sequence**:
1. `GMAIL_LIST_LABELS` - List all labels to find IDs and detect conflicts [Required]
2. `GMAIL_CREATE_LABEL` - Create a new label [Optional]
3. `GMAIL_PATCH_LABEL` - Rename or change label colors/visibility [Optional]
4. `GMAIL_DELETE_LABEL` - Delete a user-created label (irreversible) [Optional]

**Key parameters**:
- `label_name`: Max 225 chars, no commas, '/' for nesting (e.g., 'Work/Projects')
- `background_color`/`text_color`: Hex values from Gmail's predefined palette
- `id`: Label ID for PATCH/DELETE operations

**Pitfalls**:
- 400/409 error if name is blank, duplicate, or reserved (INBOX, SPAM, CATEGORY_*)
- Color specs must use Gmail's predefined palette of 102 hex values
- DELETE is permanent and removes label from all messages
- Cannot delete system labels (INBOX, SENT, DRAFT, etc.)

### 5. Apply/Remove Labels on Messages

**When to use**: User wants to label, archive, or mark emails as read/unread

**Tool sequence**:
1. `GMAIL_LIST_LABELS` - Get label IDs for custom labels [Prerequisite]
2. `GMAIL_FETCH_EMAILS` - Find target messages [Prerequisite]
3. `GMAIL_BATCH_MODIFY_MESSAGES` - Bulk add/remove labels (up to 1000 messages) [Required]
4. `GMAIL_ADD_LABEL_TO_EMAIL` - Single-message label changes [Fallback]

**Key parameters**:
- `messageIds`:
