---
name: whatsapp-automation
description: Automate WhatsApp Business tasks via Rube MCP (Composio): send messages, manage templates, upload media, and handle contacts. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, pdf, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/whatsapp-automation
---


# WhatsApp Business Automation via Rube MCP

Automate WhatsApp Business operations through Composio's WhatsApp toolkit via Rube MCP.

**Toolkit docs**: [composio.dev/toolkits/whatsapp](https://composio.dev/toolkits/whatsapp)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active WhatsApp connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `whatsapp`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas
- WhatsApp Business API account required (not regular WhatsApp)

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `whatsapp`
3. If connection is not ACTIVE, follow the returned auth link to complete WhatsApp Business setup
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Send a Text Message

**When to use**: User wants to send a text message to a WhatsApp contact

**Tool sequence**:
1. `WHATSAPP_GET_PHONE_NUMBERS` - List available business phone numbers [Prerequisite]
2. `WHATSAPP_SEND_MESSAGE` - Send a text message [Required]

**Key parameters**:
- `to`: Recipient phone number in international format (e.g., '+14155551234')
- `body`: Message text content
- `phone_number_id`: Business phone number ID to send from

**Pitfalls**:
- Phone numbers must be in international E.164 format with country code
- Messages outside the 24-hour window require approved templates
- The 24-hour window starts when the customer last messaged you
- Business-initiated conversations require template messages first

### 2. Send Template Messages

**When to use**: User wants to send pre-approved template messages for outbound communication

**Tool sequence**:
1. `WHATSAPP_GET_MESSAGE_TEMPLATES` - List available templates [Prerequisite]
2. `WHATSAPP_GET_TEMPLATE_STATUS` - Check template approval status [Optional]
3. `WHATSAPP_SEND_TEMPLATE_MESSAGE` - Send the template message [Required]

**Key parameters**:
- `template_name`: Name of the approved template
- `language_code`: Template language (e.g., 'en_US')
- `to`: Recipient phone number
- `components`: Template variable values and parameters

**Pitfalls**:
- Templates must be approved by Meta before use
- Template variables must match the expected count and format
- Sending unapproved or rejected templates returns errors
- Language code must match an approved translation of the template

### 3. Send Media Messages

**When to use**: User wants to send images, documents, or other media

**Tool sequence**:
1. `WHATSAPP_UPLOAD_MEDIA` - Upload media to WhatsApp servers [Required]
2. `WHATSAPP_SEND_MEDIA_BY_ID` - Send media using the uploaded media ID [Required]
   OR
3. `WHATSAPP_SEND_MEDIA` - Send media using a public URL [Alternative]

**Key parameters**:
- `media_url`: Public URL of the media (for SEND_MEDIA)
- `media_id`: ID from upload response (for SEND_MEDIA_BY_ID)
- `type`: Media type ('image', 'document', 'audio', 'video', 'sticker')
- `caption`: Optional caption for the media

**Pitfalls**:
- Uploaded media IDs are temporary and expire after a period
- Media size limits vary by type (images: 5MB, videos: 16MB, documents: 100MB)
- Supported formats: images (JPEG, PNG), videos (MP4, 3GPP), documents (PDF, etc.)
- SEND_MEDIA requires a publicly accessible HTTPS URL

### 4. Reply to Messages

**When to use**: User wants to reply to an incoming WhatsApp message

**Tool sequence**:
1. `WHATSAPP_SEND_REPLY` - Send a reply to a specific message [Required]

**Key parameters**:
- `message_id`: ID of the message being replied to
- `to`: Recipient phone number
- `body`: Reply text content

**Pitfalls**:
- message_id must be from a message received within the 24-hour window
- Replies appear as quoted messages in the conversation
- The original message must still exist (not deleted) for the quote to display

### 5. Manage Business Profile and Templates

**When to use**: User wants to view or manage their WhatsApp Business profile

**Tool sequence**:
1. `WHATSAPP_GET_BUSINESS_PROFILE` - Get business profile details [Optional]
2. `WHATSAPP_GET_PHONE_NUMBERS` - List registered phone numbers [Optional]
3. `WHATSAPP_GET_PHONE_NUMBER` - Get details for a specific number [Optional]
4. `WHATSAPP_CREATE_MESSAGE_TEMPLATE` - Create a new template [Optional]
5. `WHATSAPP_GET_MESSAGE_TEMPLATES` - List all templates [Optional]

**Key parameters**:
- `phone_number_id`: Business phone number ID
- `template_name`: Name for the new template
- `category`: Template category (MARKETING, UTILITY, AUTHENTICATION)
- `language`: Template language code

**Pitfalls**:
- New templates require Meta review before they can be used
- Template names must be lowercase with underscores (no spaces)
- Category affects pricing and approval criteria
- Templates have specific formatting requirements for head
